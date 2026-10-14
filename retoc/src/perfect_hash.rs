//! The perfect hash a TOC carries so the engine finds a chunk by id without a map of its own.
//!
//! A TOC without one still mounts, but the engine logs "Falling back to imperfect hashmap" for it
//! and builds a map of every chunk id at mount. This is the engine's own scheme, from
//! `FIoStoreTocResource::HashChunkIdWithSeed` and `FFileIoStoreReader::FindChunkInternal`:
//! - a chunk's bucket is its id hashed with seed 0, modulo the seed count, which the engine's
//!   writer makes half the chunk count, rounded;
//! - a bucket's seed is positive when the bucket holds several chunks: each sits at the slot its id
//!   hashed with that seed gives, modulo the chunk count;
//! - it is negative for a bucket of one chunk, which sits at slot `-seed - 1`;
//! - it is 0 for an empty bucket, which tells the engine the TOC has no such chunk.
//!
//! The TOC lists its chunks in slot order, and its directory index names chunks by slot.

use std::collections::HashSet;

const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;
/// How many seeds a bucket tries before the next seed count is tried. The game's own containers
/// never need a seed past about 3300.
const MAX_SEED_TRIES: i32 = 1 << 16;
/// The first seed a bucket tries. The game's own containers never use 1, so their writer starts
/// here too; any positive seed reads the same.
const FIRST_SEED: i32 = 2;

/// A chunk id's 12 bytes as the TOC stores them, hashed with `seed`, 0 standing for none.
pub fn hash_with_seed(seed: i32, id: &[u8; 12]) -> u64 {
    let mut hash = if seed == 0 { OFFSET_BASIS } else { seed as u64 };
    for &byte in id {
        hash = hash.wrapping_mul(PRIME) ^ byte as u64;
    }
    hash
}

/// The slot the engine reads for `id` in a TOC of `chunk_count` chunks with these seeds, or none
/// when the seeds say the TOC does not hold it. The caller still compares the id at that slot.
pub fn slot_of(seeds: &[i32], chunk_count: usize, id: &[u8; 12]) -> Option<usize> {
    if seeds.is_empty() || chunk_count == 0 {
        return None;
    }
    let seed = seeds[(hash_with_seed(0, id) % seeds.len() as u64) as usize];
    let slot = match seed {
        0 => return None,
        s if s < 0 => (-(s as i64) - 1) as usize,
        s => (hash_with_seed(s, id) % chunk_count as u64) as usize,
    };
    (slot < chunk_count).then_some(slot)
}

/// Chunks laid out for the engine's perfect hash.
#[derive(Debug, PartialEq, Eq)]
pub struct Arrangement {
    /// For each slot, the index of the chunk it holds in the order the ids were given.
    pub order: Vec<usize>,
    pub seeds: Vec<i32>,
}

/// Lays chunks out as the engine's writer does: buckets of several chunks first, the largest
/// first, each taking the first seed that puts all its chunks in free slots; then buckets of one
/// chunk, each in the next free slot. None when two ids are the same, so the TOC has to go without.
///
/// A seed only changes the low bits of a hash as far as the chunk count's power of two goes, so
/// with a count like 2, 4 or 8 two chunks of a bucket can share a slot whatever the seed. The
/// engine's writer puts such a bucket in an overflow list; its reader takes any count of seeds,
/// so here the next seed count is tried instead, which shares the chunks out into other buckets
/// and keeps every chunk on the perfect hash.
pub fn arrange(ids: &[[u8; 12]]) -> Option<Arrangement> {
    let chunk_count = ids.len();
    if chunk_count == 0 {
        return Some(Arrangement { order: vec![], seeds: vec![] });
    }
    let mut seen = HashSet::with_capacity(chunk_count);
    if !ids.iter().all(|id| seen.insert(id)) {
        return None;
    }
    let first = chunk_count.div_ceil(2);
    (first..=first + chunk_count + 16).find_map(|seed_count| arrange_with(ids, seed_count))
}

/// The layout with `seed_count` buckets, or none when a bucket finds no seed.
fn arrange_with(ids: &[[u8; 12]], seed_count: usize) -> Option<Arrangement> {
    let chunk_count = ids.len();
    let mut buckets: Vec<Vec<usize>> = vec![vec![]; seed_count];
    for (index, id) in ids.iter().enumerate() {
        buckets[(hash_with_seed(0, id) % seed_count as u64) as usize].push(index);
    }
    // Stable, so buckets of one size keep their order and the layout is the same every time.
    let mut by_size: Vec<usize> = (0..seed_count).collect();
    by_size.sort_by(|&a, &b| buckets[b].len().cmp(&buckets[a].len()));

    let mut seeds = vec![0; seed_count];
    let mut order = vec![usize::MAX; chunk_count];
    let mut slots = Vec::new();
    for &bucket_index in by_size.iter().take_while(|&&b| buckets[b].len() > 1) {
        let bucket = &buckets[bucket_index];
        let seed = (FIRST_SEED..FIRST_SEED + MAX_SEED_TRIES).find(|&seed| {
            slots.clear();
            bucket.iter().all(|&index| {
                let slot = (hash_with_seed(seed, &ids[index]) % chunk_count as u64) as usize;
                let free = order[slot] == usize::MAX && !slots.contains(&slot);
                slots.push(slot);
                free
            })
        })?;
        seeds[bucket_index] = seed;
        for (&index, &slot) in bucket.iter().zip(&slots) {
            order[slot] = index;
        }
    }

    let mut free_slots = (0..chunk_count).filter(|&slot| order[slot] == usize::MAX).collect::<Vec<_>>().into_iter();
    for &bucket_index in by_size.iter().filter(|&&b| buckets[b].len() == 1) {
        let slot = free_slots.next()?;
        seeds[bucket_index] = -(slot as i32) - 1;
        order[slot] = buckets[bucket_index][0];
    }
    Some(Arrangement { order, seeds })
}

#[cfg(test)]
mod test {
    use super::*;

    /// Ids spread like real ones: a 64-bit hash, a chunk index and a type.
    fn ids(count: usize) -> Vec<[u8; 12]> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..count)
            .map(|i| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let mut id = [0; 12];
                id[..8].copy_from_slice(&state.to_le_bytes());
                id[11] = [2, 3, 5, 9][i % 4];
                id
            })
            .collect()
    }

    /// Vectors from the same hash run over the game's own TOCs, where every chunk lands on its slot.
    #[test]
    fn hashes_ids_as_the_engine_does() {
        let id = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 5];
        assert_eq!(hash_with_seed(0, &id), 0x7b5e_3c19_6d84_2940);
        assert_eq!(hash_with_seed(2, &id), 0xbce4_cda1_1bdd_d7d7);
        assert_eq!(hash_with_seed(12345, &[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 0, 0, 0x42]), 0x7f33_db60_eaa3_7ad5);
    }

    /// Every chunk is found at the slot it was given and every slot holds one chunk, powers of two
    /// among the counts. A count with an odd factor this large keeps the engine's seed count, half
    /// the chunk count, rounded, as in the game's TOCs.
    #[test]
    fn every_chunk_is_found_where_it_was_put() {
        for count in (1..=40).chain([64, 128, 235, 256, 1000, 1024, 30_000]) {
            let ids = ids(count);
            let arrangement = arrange(&ids).expect("an arrangement");
            if [235, 1000, 30_000].contains(&count) {
                assert_eq!(arrangement.seeds.len(), count.div_ceil(2), "{count}");
            }
            let mut held: Vec<usize> = arrangement.order.clone();
            held.sort_unstable();
            assert_eq!(held, (0..count).collect::<Vec<_>>(), "{count}");
            for (slot, &index) in arrangement.order.iter().enumerate() {
                assert_eq!(slot_of(&arrangement.seeds, count, &ids[index]), Some(slot), "{count}");
            }
        }
    }

    /// An id the TOC does not hold is either told apart by its bucket or lands on a slot holding
    /// another id, so a reader comparing the id there finds nothing.
    #[test]
    fn an_absent_id_is_not_found() {
        let ids = ids(1001);
        let (held, absent) = ids.split_at(1000);
        let arrangement = arrange(held).unwrap();
        let slot = slot_of(&arrangement.seeds, held.len(), &absent[0]);
        assert!(slot.is_none_or(|slot| held[arrangement.order[slot]] != absent[0]));
    }

    #[test]
    fn the_same_ids_give_the_same_layout() {
        let ids = ids(500);
        assert_eq!(arrange(&ids), arrange(&ids));
    }

    #[test]
    fn a_repeated_id_gets_no_arrangement() {
        let mut ids = ids(10);
        ids[7] = ids[2];
        assert_eq!(arrange(&ids), None);
    }
}
