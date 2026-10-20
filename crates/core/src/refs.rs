//! Cross references as flat arrays.
//!
//! The TypeScript core kept `Map<address, number[]>` for callers and data
//! references: millions of small arrays. Here they are three arrays the page
//! reads in place — the keys in ascending order, where each key's run starts,
//! and the instruction indices one after another (compressed sparse rows) —
//! so handing them to JavaScript copies nothing.

/// References collected during a pass: (key, instruction index) pairs, in the order they were found.
#[derive(Default)]
pub struct RefBuilder {
    pairs: Vec<(i64, u32)>,
}

impl RefBuilder {
    #[inline]
    pub fn add(&mut self, key: i64, index: u32) {
        self.pairs.push((key, index));
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The same, without the references taken back: each `(key, index, before)` drops the pairs of
    /// that key and instruction among the first `before` found (one found later stays).
    pub fn build_without(mut self, retracted: &[(i64, u32, usize)]) -> RefIndex {
        if !retracted.is_empty() {
            let mut keep = vec![true; self.pairs.len()];
            for &(key, index, before) in retracted {
                for (k, pair) in self.pairs.iter().enumerate().take(before) {
                    if pair.0 == key && pair.1 == index {
                        keep[k] = false;
                    }
                }
            }
            let mut k = 0;
            self.pairs.retain(|_| {
                k += 1;
                keep[k - 1]
            });
        }
        self.build()
    }

    /// The keys with their references, each key's in the order found.
    pub fn build(mut self) -> RefIndex {
        // Indices grow through a pass, so (key, index) orders each key's references as found.
        self.pairs.sort_unstable();
        let mut keys = Vec::new();
        let mut starts = Vec::new();
        let mut values = Vec::with_capacity(self.pairs.len());
        for (k, (key, index)) in self.pairs.iter().enumerate() {
            if k == 0 || self.pairs[k - 1].0 != *key {
                keys.push(*key as f64);
                starts.push(values.len() as u32);
            }
            values.push(*index);
        }
        starts.push(values.len() as u32);
        RefIndex { keys, starts, values }
    }
}

/// Keys in ascending order; key k's references are `values[starts[k]..starts[k + 1]]`.
#[derive(Default)]
pub struct RefIndex {
    /// As JavaScript numbers: addresses beyond 2^32 read directly into a Float64Array.
    pub keys: Vec<f64>,
    pub starts: Vec<u32>,
    pub values: Vec<u32>,
}

impl RefIndex {
    pub fn find(&self, key: i64) -> Option<usize> {
        let key = key as f64;
        self.keys.binary_search_by(|k| k.partial_cmp(&key).unwrap_or(core::cmp::Ordering::Less)).ok()
    }

    pub fn get(&self, key: i64) -> &[u32] {
        match self.find(key) {
            Some(k) => &self.values[self.starts[k] as usize..self.starts[k + 1] as usize],
            None => &[],
        }
    }

    pub fn has(&self, key: i64) -> bool {
        self.find(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// A fast hasher for small keys (mnemonics, addresses): the analysis hashes one per instruction.
#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl core::hash::Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            self.write_u64(u64::from_le_bytes(buf));
        }
    }

    #[inline]
    fn write_u64(&mut self, n: u64) {
        self.hash = (self.hash.rotate_left(5) ^ n).wrapping_mul(SEED);
    }

    #[inline]
    fn write_u128(&mut self, n: u128) {
        self.write_u64(n as u64);
        self.write_u64((n >> 64) as u64);
    }

    #[inline]
    fn write_u8(&mut self, n: u8) {
        self.write_u64(n as u64)
    }

    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64)
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

pub type FxBuild = core::hash::BuildHasherDefault<FxHasher>;
pub type FxHashMap<K, V> = std::collections::HashMap<K, V, FxBuild>;
pub type FxHashSet<K> = std::collections::HashSet<K, FxBuild>;
