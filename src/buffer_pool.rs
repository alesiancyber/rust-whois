use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

// Buffer pool type
pub type BufferPool = Arc<Mutex<Vec<Vec<u8>>>>;

// RAII Buffer Pool - automatically returns buffer to pool on drop
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: BufferPool,
    buffer_size: usize,
    max_pool_size: usize,
}

impl PooledBuffer {
    pub fn new(pool: BufferPool, buffer_size: usize, max_pool_size: usize) -> Self {
        let buffer = match pool.try_lock() {
            Ok(mut p) => {
                if let Some(mut buf) = p.pop() {
                    // Ensure buffer is the right size
                    if buf.len() != buffer_size {
                        buf.resize(buffer_size, 0);
                    } else {
                        buf.clear();
                        buf.resize(buffer_size, 0);
                    }
                    debug!("Buffer retrieved from pool (remaining: {})", p.len());
                    buf
                } else {
                    debug!("Buffer pool empty, creating new buffer");
                    vec![0; buffer_size]
                }
            },
            Err(_) => {
                debug!("Buffer pool locked, creating new buffer to avoid deadlock");
                vec![0; buffer_size]
            }
        };
        
        Self { 
            buffer, 
            pool, 
            buffer_size,
            max_pool_size,
        }
    }
    
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        match self.pool.try_lock() {
            Ok(mut pool) => {
                if pool.len() < self.max_pool_size {
                    // Reset buffer to correct size and clear it
                    self.buffer.clear();
                    self.buffer.resize(self.buffer_size, 0);
                    pool.push(std::mem::take(&mut self.buffer));
                    debug!("Buffer returned to pool (size: {})", pool.len());
                } else {
                    debug!("Buffer pool full, dropping buffer");
                }
            },
            Err(_) => {
                debug!("Buffer pool locked, dropping buffer to avoid deadlock");
            }
        }
    }
} 