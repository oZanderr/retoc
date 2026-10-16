use crate::{
    EIoChunkType, FPackageId, UEPath, UEPathBuf, align_usize,
    chunk_id::FIoChunkIdRaw,
    compression::{self, CompressionMethod},
    container_header::{EIoContainerHeaderVersion, FIoContainerHeader, StoreEntry},
};
use crate::{AesKey, EIoStoreTocVersion, FIoChunkHash, FIoChunkId, FIoContainerId, FIoOffsetAndLength, FIoStoreTocCompressedBlockEntry, FIoStoreTocEntryMeta, FIoStoreTocEntryMetaFlags, Toc, ser::*};
use anyhow::{Context, Result};
use fs_err as fs;
use oodle_loader::CompressionLevel;
use rayon::prelude::*;
use std::io::Cursor;
use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

/// A block compressed with `method` at `level`, or the block as it is with method index 0 when that
/// does not make it smaller. Index 1 is a writer's one compression method.
fn compress_block(method: CompressionMethod, level: Option<CompressionLevel>, block: &[u8]) -> Result<(Vec<u8>, u8)> {
    let mut buf = Vec::new();
    compression::compress(method, level, block, &mut buf)?;
    if buf.len() < block.len() { Ok((buf, 1)) } else { Ok((block.to_vec(), 0)) }
}

/// A stored block as a writer compressing with `mine` at `level` writes it: its bytes, its method
/// index, and whether it was compressed again. A raw block and one already in `mine` are borrowed
/// as they are; only one in another method takes a buffer.
fn prepare_stored_block(block: &crate::StoredBlock, mine: Option<CompressionMethod>, level: Option<CompressionLevel>) -> Result<(std::borrow::Cow<'_, [u8]>, u8, bool)> {
    Ok(match (block.method, mine) {
        (None, _) => (block.bytes.as_slice().into(), 0, false),
        (Some(method), Some(own)) if method == own => (block.bytes.as_slice().into(), 1, false),
        (Some(_), Some(own)) => {
            let (bytes, index) = compress_block(own, level, &block.decompress()?)?;
            (bytes.into(), index, true)
        }
        (Some(_), None) => (block.decompress()?.into(), 0, true),
    })
}

/// How [`IoStoreWriter::write_stored`] wrote a chunk's blocks: copied as they were stored, or
/// decompressed and written again.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StoredCopy {
    pub copied: usize,
    pub recompressed: usize,
}

pub struct IoStoreWriter {
    #[allow(unused)]
    toc_path: PathBuf,
    toc_stream: BufWriter<fs::File>,
    cas_stream: BufWriter<fs::File>,
    toc: Toc,
    container_header: Option<FIoContainerHeader>,
    compression_method: Option<CompressionMethod>,
    compression_level: Option<CompressionLevel>,
    encryption: Option<AesKey>,
    /// How far into the cas stream the writer has got. Asking the `BufWriter` would flush it and
    /// seek the file, which stops it coalescing anything across chunks.
    cas_offset: u64,
}

impl IoStoreWriter {
    pub fn new<P: AsRef<Path>>(toc_path: P, toc_version: EIoStoreTocVersion, container_header_version: Option<EIoContainerHeaderVersion>, mount_point: UEPathBuf, compression_method: Option<CompressionMethod>) -> Result<Self> {
        let toc_path = toc_path.as_ref().to_path_buf();
        let name = toc_path.file_stem().unwrap().to_string_lossy();
        let toc_stream = BufWriter::with_capacity(1 << 20, fs::File::create(&toc_path)?);
        let cas_stream =
            BufWriter::with_capacity(4 << 20, fs::File::create(toc_path.with_extension("ucas"))?);

        let mut toc = Toc::new();
        toc.compression_block_size = 0x20000;
        toc.version = toc_version;
        toc.container_id = FIoContainerId::from_name(&name);
        toc.directory_index.mount_point = mount_point;
        toc.partition_size = u64::MAX;

        if let Some(method) = compression_method {
            toc.compression_methods.push(method);
        }

        let container_header = container_header_version.map(|v| FIoContainerHeader::new(v, toc.container_id));

        Ok(Self {
            toc_path,
            toc_stream,
            cas_stream,
            toc,
            container_header,
            compression_method,
            compression_level: None,
            encryption: None,
            cas_offset: 0,
        })
    }
    /// Builder-style override for the Oodle compression level used by chunk writes.
    /// Only applies when `compression_method` is `Some(CompressionMethod::Oodle)`.
    pub fn with_compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = Some(level);
        self
    }
    /// Override the TOC compression block size. Default is 128 KiB. Some games (e.g. Marvel Rivals)
    /// ship with 64 KiB; the runtime sizes its streaming buffers from this field, so writes must match.
    pub fn with_compression_block_size(mut self, size: u32) -> Self {
        self.toc.compression_block_size = size;
        self
    }
    /// Encrypt every written block with `key` and flag the container as encrypted, leaving the key
    /// GUID at the default so readers reach for the default-GUID key. Marvel Rivals mods use the
    /// game's own key here as obfuscation: the runtime decrypts transparently, other readers see
    /// ciphertext.
    pub fn with_encryption(mut self, key: AesKey) -> Self {
        self.toc.container_flags |= crate::EIoContainerFlags::Encrypted;
        self.encryption = Some(key);
        self
    }
    pub fn write_chunk_raw(&mut self, chunk_id_raw: FIoChunkIdRaw, path: Option<&UEPath>, data: &[u8]) -> Result<()> {
        self.write_chunk_inner(FIoChunkId::from_raw(chunk_id_raw, self.toc.version), path, data, true)
    }
    pub fn write_chunk(&mut self, chunk_id: FIoChunkId, path: Option<&UEPath>, data: &[u8]) -> Result<()> {
        self.write_chunk_inner(chunk_id, path, data, true)
    }
    pub fn write_chunk_uncompressed(&mut self, chunk_id: FIoChunkId, path: Option<&UEPath>, data: &[u8]) -> Result<()> {
        self.write_chunk_inner(chunk_id, path, data, false)
    }
    fn write_chunk_inner(&mut self, chunk_id: FIoChunkId, path: Option<&UEPath>, data: &[u8], compress: bool) -> Result<()> {
        let start_block = self.begin_chunk(path)?;
        let active_compression = if compress { self.compression_method } else { None };
        let block_size = self.toc.compression_block_size as usize;
        let blocks: Vec<&[u8]> = data.chunks(block_size).collect();

        // Hash the full payload in one pass. blake3 is SIMD-accelerated; faster than
        // per-block update accumulation in practice.
        let hash = blake3::hash(data);

        let mut any_block_compressed = false;
        for slab in blocks.chunks(self.slab_blocks(blocks.len())) {
            let compressed: Vec<(Vec<u8>, u8)> = match active_compression {
                Some(method) => {
                    let level = self.compression_level;
                    let compress_block = |block: &&[u8]| compress_block(method, level, block);
                    // Handing one block to rayon parallelises nothing and costs the calling thread a
                    // park/unpark round trip, and most package chunks are a single block.
                    if slab.len() < 2 {
                        slab.iter().map(compress_block).collect::<Result<Vec<_>>>()?
                    } else {
                        slab.par_iter().map(compress_block).collect::<Result<Vec<_>>>()?
                    }
                }
                None => slab.iter().map(|block| (block.to_vec(), 0)).collect(),
            };
            for ((written_bytes, method_index), block) in compressed.iter().zip(slab.iter()) {
                any_block_compressed |= *method_index != 0;
                self.emit_block(written_bytes, block.len() as u32, *method_index)?;
            }
        }
        self.end_chunk(chunk_id, start_block, data.len() as u64, hash.as_bytes(), any_block_compressed);
        Ok(())
    }

    /// Writes a chunk another container stores as it is stored: a block in this writer's own
    /// compression is copied, a raw one stays raw, and one in any other method is decompressed and
    /// compressed again in this writer's, or kept raw where that does not make it smaller. A chunk
    /// stored at another block size is written again from its data. `store_entry` makes it a
    /// package's export bundle, as [`Self::write_package_chunk`] does.
    pub fn write_stored(&mut self, chunk_id: FIoChunkId, path: Option<&UEPath>, stored: &crate::StoredChunk, store_entry: Option<&StoreEntry>) -> Result<StoredCopy> {
        if let Some(store_entry) = store_entry {
            let container_header = self.container_header.as_mut().expect("FIoContainerHeader is required to write package chunks");
            container_header.add_package(FPackageId(chunk_id.get_chunk_id()), store_entry.clone());
        }
        if stored.block_size != self.toc.compression_block_size {
            let compress = stored.blocks.iter().any(|block| block.method.is_some());
            let data = stored.decompress()?;
            self.write_chunk_inner(chunk_id, path, &data, compress)?;
            let blocks = data.len().div_ceil(self.toc.compression_block_size as usize);
            return Ok(StoredCopy { copied: 0, recompressed: blocks });
        }

        let start_block = self.begin_chunk(path)?;
        let (mine, level) = (self.compression_method, self.compression_level);
        let mut copy = StoredCopy::default();
        let mut any_block_compressed = false;
        for slab in stored.blocks.chunks(self.slab_blocks(stored.blocks.len())) {
            let prepared = if slab.iter().filter(|block| block.method.is_some() && block.method != mine).count() < 2 {
                slab.iter().map(|block| prepare_stored_block(block, mine, level)).collect::<Result<Vec<_>>>()?
            } else {
                slab.par_iter().map(|block| prepare_stored_block(block, mine, level)).collect::<Result<Vec<_>>>()?
            };
            for ((bytes, index, again), block) in prepared.iter().zip(slab) {
                any_block_compressed |= *index != 0;
                if *again {
                    copy.recompressed += 1;
                } else {
                    copy.copied += 1;
                }
                self.emit_block(bytes, block.uncompressed_size, *index)?;
            }
        }
        self.end_chunk(chunk_id, start_block, stored.size, &stored.hash, any_block_compressed);
        Ok(copy)
    }

    /// How many blocks go to the compressor at once: two per worker amortises rayon's dispatch
    /// without buffering much.
    fn slab_blocks(&self, blocks: usize) -> usize {
        rayon::current_num_threads().max(1).saturating_mul(2).min(blocks.max(1))
    }

    /// Files a chunk under its path, and gives the block its data starts at.
    fn begin_chunk(&mut self, path: Option<&UEPath>) -> Result<usize> {
        if let Some(path) = path {
            let index = &mut self.toc.directory_index;
            let relative_path = path.strip_prefix(&index.mount_point).with_context(|| format!("mount point {} does not contain path {path}", index.mount_point))?;
            index.add_file(relative_path, self.toc.chunks.len() as u32);
        }
        Ok(self.toc.compression_blocks.len())
    }

    /// Writes one block, encrypted when the container is, and adds its entry.
    fn emit_block(&mut self, bytes: &[u8], uncompressed_size: u32, method_index: u8) -> Result<()> {
        // Encrypted blocks are stored padded out to the AES block size while the entry keeps the
        // unpadded length, which is what the read path aligns back up.
        let stored_size = match &self.encryption {
            Some(key) => {
                use aes::cipher::BlockEncrypt;
                let mut padded = bytes.to_vec();
                padded.resize(align_usize(padded.len(), 16), 0);
                for aes_block in padded.chunks_mut(16) {
                    key.0.encrypt_block(aes_block.into());
                }
                self.cas_stream.write_all(&padded)?;
                padded.len() as u64
            }
            None => {
                self.cas_stream.write_all(bytes)?;
                bytes.len() as u64
            }
        };
        self.toc.compression_blocks.push(FIoStoreTocCompressedBlockEntry::new(self.cas_offset, bytes.len() as u32, uncompressed_size, method_index));
        self.cas_offset += stored_size;
        Ok(())
    }

    /// Records a chunk whose blocks start at `start_block`.
    fn end_chunk(&mut self, chunk_id: FIoChunkId, start_block: usize, size: u64, hash: &[u8; 32], any_block_compressed: bool) {
        let flags = if any_block_compressed { FIoStoreTocEntryMetaFlags::Compressed } else { FIoStoreTocEntryMetaFlags::empty() };
        let meta = FIoStoreTocEntryMeta { chunk_hash: FIoChunkHash::from_blake3(hash), flags };
        let offset_and_length = FIoOffsetAndLength::new(start_block as u64 * self.toc.compression_block_size as u64, size);
        self.toc.chunks.push(chunk_id.with_version(self.toc.version));
        self.toc.chunk_offset_lengths.push(offset_and_length);
        self.toc.chunk_metas.push(meta);
    }

    pub fn write_package_chunk(&mut self, chunk_id: FIoChunkId, path: Option<&UEPath>, data: &[u8], store_entry: &StoreEntry) -> Result<()> {
        let container_header = self.container_header.as_mut().expect("FIoContainerHeader is required to write package chunks");
        container_header.add_package(FPackageId(chunk_id.get_chunk_id()), store_entry.clone());
        self.write_chunk(chunk_id, path, data)
    }
    /// Same as `write_package_chunk` but stores the export-bundle chunk uncompressed, preserving a
    /// source container's decision to ship a package raw. Header linkage is identical.
    pub fn write_package_chunk_uncompressed(&mut self, chunk_id: FIoChunkId, path: Option<&UEPath>, data: &[u8], store_entry: &StoreEntry) -> Result<()> {
        let container_header = self.container_header.as_mut().expect("FIoContainerHeader is required to write package chunks");
        container_header.add_package(FPackageId(chunk_id.get_chunk_id()), store_entry.clone());
        self.write_chunk_uncompressed(chunk_id, path, data)
    }
    pub fn add_localized_package(&mut self, package_culture: &str, source_package_name: &str, localized_package_id: FPackageId) -> Result<()> {
        let container_header = self.container_header.as_mut().expect("FIoContainerHeader is required to add localized packages");
        container_header.add_localized_package(package_culture, source_package_name, localized_package_id)
    }
    pub fn add_package_redirect(&mut self, source_package_name: &str, redirect_package_id: FPackageId) -> Result<()> {
        let container_header = self.container_header.as_mut().expect("FIoContainerHeader is required to add package redirects");
        container_header.add_package_redirect(source_package_name, redirect_package_id)
    }
    pub fn container_version(&self) -> EIoStoreTocVersion {
        self.toc.version
    }
    pub fn container_header_version(&self) -> EIoContainerHeaderVersion {
        self.container_header.as_ref().unwrap().version
    }
    pub fn finalize(mut self) -> Result<()> {
        if let Some(container_header) = &self.container_header {
            let mut chunk_buffer = vec![];
            container_header.serialize(&mut Cursor::new(&mut chunk_buffer))?;
            // container header is always aligned for AES for some reason
            chunk_buffer.resize(align_usize(chunk_buffer.len(), 16), 0);

            let chunk_id = FIoChunkId::create(container_header.container_id.0, 0, EIoChunkType::ContainerHeader);
            // container header must NOT be compressed
            self.write_chunk_uncompressed(chunk_id, None, &chunk_buffer)?;
        }
        self.toc_stream.ser(&self.toc)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fs_err as fs;

    #[test]
    fn test_write_container() -> Result<()> {
        fs::create_dir("out").ok();
        let mut writer = IoStoreWriter::new("out/new.utoc", EIoStoreTocVersion::PerfectHashWithOverflow, Some(EIoContainerHeaderVersion::OptionalSegmentPackages), "../../..".into(), None)?;

        let data = fs::read("tests/UE5.3/ScriptObjects.bin")?;
        writer.write_chunk_raw(FIoChunkIdRaw { id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5] }, Some(UEPath::new("../../../asdf/asdf/dasf/script_objects.bin")), &data)?;
        writer.finalize()?;
        Ok(())
    }

    /// A written TOC carries the engine's perfect hash: each chunk is where its seeds say, its file
    /// is still named for it, and its data reads back. Uncompressed, so no Oodle library is needed.
    #[test]
    fn written_toc_finds_every_chunk_by_its_perfect_hash() -> Result<()> {
        use crate::{Config, FIoChunkIdRaw, perfect_hash};
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!("retoc-perfect-hash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let toc_path = dir.join("Hashed_P.utoc");

        let mut writer = IoStoreWriter::new(&toc_path, EIoStoreTocVersion::PerfectHashWithOverflow, None, "../../..".into(), None)?;
        let mut written = vec![];
        for i in 0..97u32 {
            let mut id = [0; 12];
            id[..4].copy_from_slice(&i.wrapping_mul(0x9e37_79b9).to_le_bytes());
            id[4..8].copy_from_slice(&i.to_le_bytes());
            id[11] = if i % 3 == 0 { 3 } else { 2 };
            let raw = FIoChunkIdRaw { id };
            let data: Vec<u8> = (0..(100 + i * 7)).map(|b| (b ^ i) as u8).collect();
            // A few chunks without a file, as bulk data and the container header have.
            let path = (i % 10 != 0).then(|| format!("../../../Marvel/Content/Test/File{i}.uasset"));
            writer.write_chunk_raw(raw, path.as_deref().map(UEPath::new), &data)?;
            written.push((raw, path, data));
        }
        writer.finalize()?;

        let raw_toc = fs::read(&toc_path)?;
        let seeds_count = u32::from_le_bytes(raw_toc[84..88].try_into()?);
        assert_eq!(seeds_count, 49, "half the 97 chunks, rounded");

        let toc: Toc = std::io::BufReader::new(fs::File::open(&toc_path)?).de_ctx(Arc::new(Config::default()))?;
        assert_eq!(toc.chunk_perfect_hash_seeds.len(), 49);
        let mut cas = std::io::BufReader::new(fs::File::open(toc_path.with_extension("ucas"))?);
        for (raw, path, data) in &written {
            let slot = perfect_hash::slot_of(&toc.chunk_perfect_hash_seeds, toc.chunks.len(), &raw.id).expect("a slot");
            assert_eq!(toc.chunks[slot].get_raw().id, raw.id);
            assert_eq!(&toc.read(&mut cas, slot as u32)?, data);
            assert_eq!(&toc.file_name(FIoChunkId::from_raw(FIoChunkIdRaw { id: raw.id }, toc.version)), path);
        }

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Uncompressed on purpose: it exercises the encrypt path without needing an Oodle library.
    #[test]
    fn encrypted_container_round_trips() -> Result<()> {
        use crate::{Config, FGuid};
        use std::collections::HashMap;
        use std::sync::Arc;

        const KEY: &str = "0C263D8C22DCB085894899C3A3796383E9BF9DE0CBFB08C9BF2DEF2E84F29D74";
        const BLOCK_SIZE: u32 = 0x10000;

        let dir = std::env::temp_dir().join(format!("retoc-encrypted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let toc_path = dir.join("encrypted.utoc");

        // Sized to leave a partial trailing block, so padding is not incidental.
        let payload: Vec<u8> = (0..300_003u32).map(|i| (i % 251) as u8).collect();
        let key: AesKey = KEY.parse()?;

        let mut writer = IoStoreWriter::new(&toc_path, EIoStoreTocVersion::PerfectHashWithOverflow, None, "../../..".into(), None)?
            .with_compression_block_size(BLOCK_SIZE)
            .with_encryption(key.clone());
        writer.write_chunk_raw(FIoChunkIdRaw { id: [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 5] }, Some(UEPath::new("../../../Marvel/Content/Test/Payload.bin")), &payload)?;
        writer.finalize()?;

        let raw = fs::read(&toc_path)?;
        assert_eq!(raw[80] & 0b0010, 0b0010, "Encrypted container flag not set");
        assert!(raw[64..80].iter().all(|&b| b == 0), "key GUID must stay all zero");

        let config = Arc::new(Config { aes_keys: HashMap::from([(FGuid::default(), key)]), ..Default::default() });
        let mut toc_stream = std::io::BufReader::new(fs::File::open(&toc_path)?);
        let toc: Toc = toc_stream.de_ctx(config)?;

        let expected_blocks = payload.len().div_ceil(BLOCK_SIZE as usize);
        assert_eq!(toc.compression_blocks.len(), expected_blocks);
        for pair in toc.compression_blocks.windows(2) {
            let gap = pair[1].get_offset() - pair[0].get_offset();
            assert_eq!(gap, align_usize(pair[0].get_compressed_size() as usize, 16) as u64);
        }

        let mut cas = std::io::BufReader::new(fs::File::open(toc_path.with_extension("ucas"))?);
        assert_eq!(toc.read(&mut cas, 0)?, payload);

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Chunks for the stored-copy tests: compressible ones across several blocks, one that does
    /// not compress, so it is stored raw, and one shorter than a block.
    fn stored_payloads() -> Vec<Vec<u8>> {
        let mut noise = 0x2545_f491u32;
        let incompressible: Vec<u8> = (0..70_000)
            .map(|_| {
                noise ^= noise << 13;
                noise ^= noise >> 17;
                noise ^= noise << 5;
                noise as u8
            })
            .collect();
        vec![(0..300_003u32).map(|i| (i % 251) as u8).collect(), incompressible, b"short".repeat(30)]
    }

    struct Written {
        dir: PathBuf,
        toc: PathBuf,
        payloads: Vec<Vec<u8>>,
    }

    /// A container of [`stored_payloads`] in `method`, blocks of `block_size`, encrypted with `key`.
    fn written(tag: &str, method: Option<CompressionMethod>, block_size: u32, key: Option<&AesKey>) -> Result<Written> {
        let dir = std::env::temp_dir().join(format!("retoc-stored-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let toc = dir.join("Source_P.utoc");
        let mut writer = IoStoreWriter::new(&toc, EIoStoreTocVersion::PerfectHashWithOverflow, None, "../../..".into(), method)?.with_compression_block_size(block_size);
        if let Some(key) = key {
            writer = writer.with_encryption(key.clone());
        }
        let payloads = stored_payloads();
        for (at, data) in payloads.iter().enumerate() {
            let path = format!("../../../Marvel/Content/Stored/Chunk{at}.bin");
            writer.write_chunk(FIoChunkId::create(at as u64 + 7, 0, EIoChunkType::BulkData), Some(UEPath::new(&path)), data)?;
        }
        writer.finalize()?;
        Ok(Written { dir, toc, payloads })
    }

    const STORED_KEY: &str = "0C263D8C22DCB085894899C3A3796383E9BF9DE0CBFB08C9BF2DEF2E84F29D74";

    fn keyed_config() -> Result<std::sync::Arc<crate::Config>> {
        let key: AesKey = STORED_KEY.parse()?;
        Ok(std::sync::Arc::new(crate::Config {
            aes_keys: std::collections::HashMap::from([(crate::FGuid::default(), key)]),
            ..Default::default()
        }))
    }

    /// Copies every chunk of `from` into a new container written by `into`, and gives what the
    /// copies came to, with the new container open.
    fn copy_stored(from: &Written, into: IoStoreWriter, into_toc: &Path) -> Result<(StoredCopy, crate::iostore::IoStoreContainer)> {
        use crate::iostore::{IoStoreContainer, IoStoreTrait};
        let source = IoStoreContainer::open(&from.toc, keyed_config()?)?;
        let mut into = into;
        let mut total = StoredCopy::default();
        for chunk in source.chunks() {
            let stored = chunk.read_stored()?.expect("stored");
            assert_eq!(stored.decompress()?, chunk.read()?);
            let path = chunk.path();
            let copy = into.write_stored(chunk.id(), path.as_deref().map(UEPath::new), &stored, None)?;
            total.copied += copy.copied;
            total.recompressed += copy.recompressed;
        }
        into.finalize()?;
        Ok((total, IoStoreContainer::open(into_toc, keyed_config()?)?))
    }

    /// Every chunk of `copy` reads back as its payload, under its path, with its blake3 hash.
    fn holds_payloads(copy: &crate::iostore::IoStoreContainer, payloads: &[Vec<u8>]) -> Result<()> {
        use crate::iostore::IoStoreTrait;
        for (at, data) in payloads.iter().enumerate() {
            let id = FIoChunkId::create(at as u64 + 7, 0, EIoChunkType::BulkData);
            assert_eq!(&copy.read(id)?, data, "chunk {at}");
            assert_eq!(copy.chunk_path(id).as_deref(), Some(format!("../../../Marvel/Content/Stored/Chunk{at}.bin").as_str()));
            let chunk = copy.chunks().find(|chunk| chunk.id() == id.with_version(EIoStoreTocVersion::PerfectHashWithOverflow)).expect("listed");
            assert_eq!(chunk.hash().0[..20], blake3::hash(data).as_bytes()[..20], "chunk {at}'s hash");
        }
        Ok(())
    }

    /// Blocks in the copy's own compression are copied byte for byte, plain or encrypted on either
    /// side, and every chunk reads back whole.
    #[test]
    fn stored_blocks_copy_between_plain_and_encrypted_containers() -> Result<()> {
        let key: AesKey = STORED_KEY.parse()?;
        for (from_key, into_key) in [(None, None), (None, Some(&key)), (Some(&key), None), (Some(&key), Some(&key))] {
            let tag = format!("{}{}", from_key.is_some() as u8, into_key.is_some() as u8);
            let from = written(&format!("from{tag}"), Some(CompressionMethod::Zlib), 0x10000, from_key)?;
            let into_toc = from.dir.join("Copy_P.utoc");
            let mut into = IoStoreWriter::new(&into_toc, EIoStoreTocVersion::PerfectHashWithOverflow, None, "../../..".into(), Some(CompressionMethod::Zlib))?.with_compression_block_size(0x10000);
            if let Some(key) = into_key {
                into = into.with_encryption(key.clone());
            }
            let (copy, opened) = copy_stored(&from, into, &into_toc)?;
            assert_eq!(copy.recompressed, 0, "{tag}");
            assert!(copy.copied >= 6, "{tag}: {copy:?}");
            holds_payloads(&opened, &from.payloads)?;
            let source = crate::iostore::IoStoreContainer::open(&from.toc, keyed_config()?)?;
            for at in 0..from.payloads.len() {
                let id = FIoChunkId::create(at as u64 + 7, 0, EIoChunkType::BulkData);
                assert_eq!(source.read_stored(id)?.expect("stored").blocks, opened.read_stored(id)?.expect("stored").blocks, "{tag}: chunk {at}'s blocks");
            }
            let _ = std::fs::remove_dir_all(&from.dir);
        }
        Ok(())
    }

    /// A block in another method is compressed again in the copy's, a raw one stays raw, a copy
    /// without compression stores every block raw, and one at another block size is written again
    /// at its own.
    #[test]
    fn stored_blocks_in_another_method_or_block_size_are_written_again() -> Result<()> {
        let from = written("methods", Some(CompressionMethod::Zlib), 0x10000, None)?;
        let compressed_blocks = 300_003usize.div_ceil(0x10000) + 1;

        let zstd_toc = from.dir.join("Zstd_P.utoc");
        let zstd = IoStoreWriter::new(&zstd_toc, EIoStoreTocVersion::PerfectHashWithOverflow, None, "../../..".into(), Some(CompressionMethod::Zstd))?.with_compression_block_size(0x10000);
        let (copy, opened) = copy_stored(&from, zstd, &zstd_toc)?;
        assert_eq!(copy.recompressed, compressed_blocks, "{copy:?}");
        assert_eq!(copy.copied, 70_000usize.div_ceil(0x10000), "the raw blocks: {copy:?}");
        holds_payloads(&opened, &from.payloads)?;
        let first = opened.read_stored(FIoChunkId::create(7, 0, EIoChunkType::BulkData))?.expect("stored");
        assert!(first.blocks.iter().all(|block| block.method == Some(CompressionMethod::Zstd)));
        drop(opened);

        let plain_toc = from.dir.join("Plain_P.utoc");
        let plain = IoStoreWriter::new(&plain_toc, EIoStoreTocVersion::PerfectHashWithOverflow, None, "../../..".into(), None)?.with_compression_block_size(0x10000);
        let (_, opened) = copy_stored(&from, plain, &plain_toc)?;
        holds_payloads(&opened, &from.payloads)?;
        let first = opened.read_stored(FIoChunkId::create(7, 0, EIoChunkType::BulkData))?.expect("stored");
        assert!(first.blocks.iter().all(|block| block.method.is_none()));
        drop(opened);

        let wide_toc = from.dir.join("Wide_P.utoc");
        let wide = IoStoreWriter::new(&wide_toc, EIoStoreTocVersion::PerfectHashWithOverflow, None, "../../..".into(), Some(CompressionMethod::Zlib))?.with_compression_block_size(0x20000);
        let (copy, opened) = copy_stored(&from, wide, &wide_toc)?;
        assert_eq!(copy.copied, 0, "{copy:?}");
        holds_payloads(&opened, &from.payloads)?;
        let first = opened.read_stored(FIoChunkId::create(7, 0, EIoChunkType::BulkData))?.expect("stored");
        assert_eq!(first.blocks.len(), 300_003usize.div_ceil(0x20000));
        drop(opened);

        let _ = std::fs::remove_dir_all(&from.dir);
        Ok(())
    }
}
