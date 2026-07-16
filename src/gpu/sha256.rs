use super::backend::GpuBackend;
use wgpu::util::DeviceExt;

pub struct GpuSha256<'a> {
    backend: &'a GpuBackend,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
}

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Pad message per SHA-256 spec using the provided total bit length.
/// Returns big-endian u32 words.
fn pad_message_with_length(data: &[u8], total_bit_len: u64) -> Vec<u32> {
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&total_bit_len.to_be_bytes());
    assert!(padded.len().is_multiple_of(64));

    padded
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Pad message per SHA-256 spec. Returns big-endian u32 words.
fn pad_message(data: &[u8]) -> Vec<u32> {
    pad_message_with_length(data, data.len() as u64 * 8)
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
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
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

    /// Dispatch `num_blocks` SHA-256 blocks to the GPU, starting from `init_state`.
    /// Returns the updated 8-word hash state.
    fn dispatch_blocks(
        &self,
        words: &[u32],
        num_blocks: u32,
        init_state: &[u32; 8],
    ) -> anyhow::Result<[u32; 8]> {
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

        // Upload init_state as little-endian u32 bytes
        let init_bytes: Vec<u8> = init_state.iter().flat_map(|w| w.to_le_bytes()).collect();
        let init_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("sha256_init_state"),
            contents: &init_bytes,
            usage: wgpu::BufferUsages::STORAGE,
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
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: init_buf.as_entire_binding(),
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

        let mapped = slice.get_mapped_range();
        // GPU writes u32 values in native (little-endian) byte order.
        // Read them back as little-endian to recover the original integer value.
        let mut out = [0u32; 8];
        for (i, chunk) in mapped.chunks_exact(4).enumerate() {
            out[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        drop(mapped);
        staging_buf.unmap();

        Ok(out)
    }

    pub fn hash(&self, data: &[u8]) -> String {
        let words = pad_message(data);
        let num_blocks = (words.len() / 16) as u32;
        let state = self
            .dispatch_blocks(&words, num_blocks, &SHA256_IV)
            .expect("GPU sha256 dispatch failed");
        state.iter().map(|w| format!("{w:08x}")).collect()
    }

    /// Hash `data` in 64 KiB GPU batches (1024 × 64-byte blocks per dispatch).
    /// For data that fits in a single batch, behavior is identical to `hash()`.
    pub fn hash_chunked(&self, data: &[u8]) -> anyhow::Result<String> {
        const BATCH_BYTES: usize = 1024 * 64; // 1024 blocks × 64 bytes = 64 KiB

        if data.is_empty() {
            return Ok(self.hash(data));
        }

        let total_bytes = data.len();
        let total_bits = total_bytes as u64 * 8;

        let mut state = SHA256_IV;
        let mut offset = 0;

        while offset < total_bytes {
            let remaining = total_bytes - offset;
            let is_last = remaining <= BATCH_BYTES;

            let chunk_words: Vec<u32> = if is_last {
                // Apply full SHA-256 padding using the TOTAL message bit length
                let chunk = &data[offset..];
                pad_message_with_length(chunk, total_bits)
            } else {
                // Raw blocks, no padding — exact BATCH_BYTES, must be multiple of 64
                let raw = &data[offset..offset + BATCH_BYTES];
                raw.chunks_exact(4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect()
            };

            let num_blocks = (chunk_words.len() / 16) as u32;
            state = self.dispatch_blocks(&chunk_words, num_blocks, &state)?;

            if is_last {
                break;
            }
            offset += BATCH_BYTES;
        }

        Ok(state.iter().map(|w| format!("{w:08x}")).collect())
    }
}
