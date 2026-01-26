use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

// Buffer pool type
pub type BufferPool = Arc<Mutex<Vec<Vec<u8>>>>;

/// RAII Buffer Pool - automatically returns buffer to pool on drop
/// 
/// Implements `Deref` and `DerefMut` for ergonomic access to the underlying buffer.
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: BufferPool,
    buffer_size: usize,
    max_pool_size: usize,
}

impl PooledBuffer {
    #[must_use]
    pub fn new(pool: BufferPool, buffer_size: usize, max_pool_size: usize) -> Self {
        let buffer = match pool.try_lock() {
            Ok(mut p) => {
                if let Some(mut buf) = p.pop() {
                    // Ensure buffer is the right size, reusing allocation
                    if buf.len() != buffer_size {
                        buf.resize(buffer_size, 0);
                    }
                    // Buffer contents will be overwritten by reader, no need to zero
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
}

impl Deref for PooledBuffer {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        match self.pool.try_lock() {
            Ok(mut pool) => {
                if pool.len() < self.max_pool_size {
                    // Return buffer to pool - resize only if needed
                    // Contents don't need zeroing; will be overwritten on reuse
                    if self.buffer.capacity() >= self.buffer_size {
                        // Reuse existing allocation, just set correct length
                        self.buffer.truncate(self.buffer_size);
                        if self.buffer.len() < self.buffer_size {
                            self.buffer.resize(self.buffer_size, 0);
                        }
                    }
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