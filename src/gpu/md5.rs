use super::backend::GpuBackend;
use wgpu::util::DeviceExt;

pub struct GpuMd5<'a> {
    backend: &'a GpuBackend,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
}

/// Pad message per MD5 spec. Returns little-endian u32 words.
fn pad_message_md5(data: &[u8]) -> Vec<u32> {
    let bit_len = data.len() as u64 * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    // Append 64-bit little-endian bit length
    padded.extend_from_slice(&bit_len.to_le_bytes());
    assert!(padded.len().is_multiple_of(64));

    // Convert to little-endian u32 words
    padded
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

impl<'a> GpuMd5<'a> {
    pub fn new(backend: &'a GpuBackend) -> Self {
        let device = backend.device();

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("md5"),
            source: wgpu::ShaderSource::Wgsl(include_str!("md5.wgsl").into()),
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("md5_bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("md5_pipeline_layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("md5_pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: "main",
            compilation_options: Default::default(),
            cache: None,
        });

        Self {
            backend,
            pipeline,
            bind_group_layout,
        }
    }

    pub fn hash(&self, data: &[u8]) -> String {
        let words = pad_message_md5(data);
        let num_blocks = (words.len() / 16) as u32;

        let device = self.backend.device();
        let queue = self.backend.queue();

        // MD5 words are already LE u32s — upload as native bytes
        let msg_bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();

        let msg_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("md5_msg"),
            contents: &msg_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });

        // MD5 digest is 4 × u32 = 16 bytes
        let digest_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("md5_digest"),
            size: 16,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let staging_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("md5_staging"),
            size: 16,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        let mut params_bytes = [0u8; 16];
        params_bytes[..4].copy_from_slice(&num_blocks.to_ne_bytes());
        let params_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("md5_params"),
            contents: &params_bytes,
            usage: wgpu::BufferUsages::UNIFORM,
        });

        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("md5_bg"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: msg_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: digest_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: params_buf.as_entire_binding(),
                },
            ],
        });

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("md5_encoder"),
        });

        {
            let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("md5_pass"),
                timestamp_writes: None,
            });
            cpass.set_pipeline(&self.pipeline);
            cpass.set_bind_group(0, &bind_group, &[]);
            cpass.dispatch_workgroups(1, 1, 1);
        }

        encoder.copy_buffer_to_buffer(&digest_buf, 0, &staging_buf, 0, 16);
        queue.submit(std::iter::once(encoder.finish()));

        let slice = staging_buf.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        device.poll(wgpu::Maintain::Wait);
        rx.recv().unwrap().unwrap();

        let data = slice.get_mapped_range();
        // MD5 digest: 4 LE u32 words, output as little-endian hex
        let digest: Vec<u32> = data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        drop(data);
        staging_buf.unmap();

        // Format each word as little-endian bytes in hex
        digest
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
