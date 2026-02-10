use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use crossbeam::queue::ArrayQueue;
use tracing::debug;

// Lock-free buffer pool using crossbeam's ArrayQueue
// Never blocks - push/pop operations are wait-free
pub type BufferPool = Arc<ArrayQueue<Vec<u8>>>;

/// RAII Buffer Pool - automatically returns buffer to pool on drop
///
/// Implements `Deref` and `DerefMut` for ergonomic access to the underlying buffer.
/// Uses lock-free queue for zero contention under high concurrency.
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: BufferPool,
    buffer_size: usize,
}

impl PooledBuffer {
    #[must_use]
    pub fn new(pool: BufferPool, buffer_size: usize, _max_pool_size: usize) -> Self {
        let buffer = match pool.pop() {
            Some(mut buf) => {
                // Reuse allocation if capacity is sufficient
                // Just set length without reallocating
                if buf.capacity() >= buffer_size {
                    buf.resize(buffer_size, 0);
                } else {
                    // Capacity too small, allocate new buffer
                    debug!("Buffer capacity insufficient, allocating new buffer");
                    buf = vec![0; buffer_size];
                }
                // Buffer contents will be overwritten by reader, no need to zero
                debug!("Buffer retrieved from lock-free pool (remaining: {})", pool.len());
                buf
            }
            None => {
                debug!("Buffer pool empty, creating new buffer");
                vec![0; buffer_size]
            }
        };

        Self {
            buffer,
            pool,
            buffer_size,
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
        // Return buffer to pool - resize only if needed
        // Contents don't need zeroing; will be overwritten on reuse
        if self.buffer.capacity() >= self.buffer_size {
            // Reuse existing allocation, just set correct length
            self.buffer.truncate(self.buffer_size);
            if self.buffer.len() < self.buffer_size {
                self.buffer.resize(self.buffer_size, 0);
            }
        }

        // Try to return buffer to pool - push() is lock-free and never blocks
        match self.pool.push(std::mem::take(&mut self.buffer)) {
            Ok(_) => {
                debug!("Buffer returned to lock-free pool (size: {})", self.pool.len());
            }
            Err(_) => {
                // Pool is full - buffer will be dropped (that's fine)
                debug!("Buffer pool full, dropping buffer");
            }
        }
    }
}
