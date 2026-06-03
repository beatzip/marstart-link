//! Thread-safe bounded ring buffer for metric samples.
//!
//! Используется для хранения окон latency / loss / throughput.
//! Не зависит от async runtime, безопасен для использования из tokio задач.

use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Debug)]
pub struct RingBuffer<T: Clone> {
    inner: Arc<RwLock<RingInner<T>>>,
}

#[derive(Debug)]
struct RingInner<T> {
    data: Vec<Option<T>>,
    head: usize,
    len: usize,
    cap: usize,
}

impl<T: Clone> RingBuffer<T> {
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "RingBuffer capacity must be > 0");
        Self {
            inner: Arc::new(RwLock::new(RingInner {
                data: vec![None; cap],
                head: 0,
                len: 0,
                cap,
            })),
        }
    }

    pub fn push(&self, value: T) {
        let mut g = self.inner.write();
        let idx = (g.head + g.len) % g.cap;
        if g.len == g.cap {
            // overwrite oldest
            g.data[g.head] = Some(value);
            g.head = (g.head + 1) % g.cap;
        } else {
            g.data[idx] = Some(value);
            g.len += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.inner.read().cap
    }

    /// Snapshot ordered from oldest to newest.
    pub fn snapshot(&self) -> Vec<T> {
        let g = self.inner.read();
        let mut out = Vec::with_capacity(g.len);
        for i in 0..g.len {
            let idx = (g.head + i) % g.cap;
            if let Some(v) = &g.data[idx] {
                out.push(v.clone());
            }
        }
        out
    }

    pub fn clear(&self) {
        let mut g = self.inner.write();
        for slot in g.data.iter_mut() {
            *slot = None;
        }
        g.head = 0;
        g.len = 0;
    }
}

impl<T: Clone> Clone for RingBuffer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_snapshot_order() {
        let r = RingBuffer::new(3);
        r.push(1);
        r.push(2);
        r.push(3);
        assert_eq!(r.snapshot(), vec![1, 2, 3]);
    }

    #[test]
    fn overflow_overwrites_oldest() {
        let r = RingBuffer::new(3);
        r.push(1);
        r.push(2);
        r.push(3);
        r.push(4);
        r.push(5);
        assert_eq!(r.snapshot(), vec![3, 4, 5]);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn clear_resets_state() {
        let r = RingBuffer::new(3);
        r.push(1);
        r.push(2);
        r.clear();
        assert!(r.is_empty());
        assert_eq!(r.snapshot(), Vec::<i32>::new());
    }

    #[test]
    fn clone_shares_storage() {
        let a: RingBuffer<i32> = RingBuffer::new(2);
        let b = a.clone();
        a.push(7);
        assert_eq!(b.snapshot(), vec![7]);
    }
}
