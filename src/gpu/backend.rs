use wgpu::Backends;

/// Known software renderer name substrings to skip.
const SW_RENDERER_NAMES: &[&str] = &["warp", "llvmpipe", "software", "basic render"];

pub struct GpuBackend {
    device: wgpu::Device,
    queue: wgpu::Queue,
    adapter_name: String,
}

impl GpuBackend {
    /// Detect a usable GPU adapter. Returns None if no real GPU is available.
    /// Skips software renderers (WARP, llvmpipe) as they are always slower than CPU.
    pub fn detect() -> Option<Self> {
        pollster::block_on(Self::detect_async())
    }

    async fn detect_async() -> Option<Self> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: Backends::all(),
            ..Default::default()
        });

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await?;

        let info = adapter.get_info();
        let name_lower = info.name.to_lowercase();

        // Skip software renderers
        if SW_RENDERER_NAMES.iter().any(|sw| name_lower.contains(sw)) {
            return None;
        }

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor::default(), None)
            .await
            .ok()?;

        Some(Self {
            device,
            queue,
            adapter_name: info.name,
        })
    }

    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    pub fn device(&self) -> &wgpu::Device {
        &self.device
    }

    pub fn queue(&self) -> &wgpu::Queue {
        &self.queue
    }
}
