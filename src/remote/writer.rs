use anyhow::Result;
use opendal::blocking;
use std::io::Write;

pub struct RemoteWriter {
    buf: Vec<u8>,
    op: blocking::Operator,
    path: String,
    done: bool,
}

impl RemoteWriter {
    pub fn new(op: blocking::Operator, path: String) -> Self {
        Self {
            buf: Vec::new(),
            op,
            path,
            done: false,
        }
    }

    pub fn finish(mut self) -> Result<()> {
        let data = std::mem::take(&mut self.buf);
        self.op.write(&self.path, data)?;
        self.done = true;
        Ok(())
    }
}

impl Write for RemoteWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for RemoteWriter {
    fn drop(&mut self) {
        if !self.done && !self.buf.is_empty() {
            if let Err(e) = self.op.write(&self.path, std::mem::take(&mut self.buf)) {
                eprintln!("blazehash: error: remote write failed: {e}");
            }
        }
    }
}
