use super::backend::GpuBackend;
use wgpu::util::DeviceExt;

pub struct GpuSha256<'a> {
    backend: &'a GpuBackend,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
}

/// Pad message per SHA-256 spec. Returns big-endian u32 words.
fn pad_message(data: &[u8]) -> Vec<u32> {
    let bit_len = data.len() as u64 * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    assert!(padded.len() % 64 == 0);

    padded
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

impl<'a> GpuSha256<'a> {
    pub fn new(backend: &'a GpuBackend) -> Self {
        let device = backend.device();

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("sha256"),
            source: wgpu::ShaderSource::Wgsl(include_str!("sha256.wgsl").into()),
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("sha256_bgl"),
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
            label: Some("sha256_pipeline_layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("sha256_pipeline"),
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
        let words = pad_message(data);
        let num_blocks = (words.len() / 16) as u32;

        let device = self.backend.device();
        let queue = self.backend.queue();

        // Upload message as little-endian bytes so GPU reads the correct integer values
        let msg_bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();

        let msg_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("sha256_msg"),
            contents: &msg_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });

        let digest_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("sha256_digest"),
            size: 32,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let staging_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("sha256_staging"),
            size: 32,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        // Params: num_blocks as u32, padded to 16 bytes (uniform alignment)
        let mut params_bytes = [0u8; 16];
        params_bytes[..4].copy_from_slice(&num_blocks.to_ne_bytes());
        let params_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("sha256_params"),
            contents: &params_bytes,
            usage: wgpu::BufferUsages::UNIFORM,
        });

        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("sha256_bg"),
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
            label: Some("sha256_encoder"),
        });

        {
            let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("sha256_pass"),
                timestamp_writes: None,
            });
            cpass.set_pipeline(&self.pipeline);
            cpass.set_bind_group(0, &bind_group, &[]);
            cpass.dispatch_workgroups(1, 1, 1);
        }

        encoder.copy_buffer_to_buffer(&digest_buf, 0, &staging_buf, 0, 32);
        queue.submit(std::iter::once(encoder.finish()));

        // Read back result
        let slice = staging_buf.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        device.poll(wgpu::Maintain::Wait);
        rx.recv().unwrap().unwrap();

        let data = slice.get_mapped_range();
        // GPU writes u32 values in native (little-endian) byte order.
        // Read them back as little-endian to recover the original integer value.
        let digest: Vec<u32> = data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        drop(data);
        staging_buf.unmap();

        digest.iter().map(|w| format!("{w:08x}")).collect()
    }
}
