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
    io::{BufWriter, Seek, Write},
    path::{Path, PathBuf},
};

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
}

impl IoStoreWriter {
    pub fn new<P: AsRef<Path>>(toc_path: P, toc_version: EIoStoreTocVersion, container_header_version: Option<EIoContainerHeaderVersion>, mount_point: UEPathBuf, compression_method: Option<CompressionMethod>) -> Result<Self> {
        let toc_path = toc_path.as_ref().to_path_buf();
        let name = toc_path.file_stem().unwrap().to_string_lossy();
        let toc_stream = BufWriter::new(fs::File::create(&toc_path)?);
        let cas_stream = BufWriter::new(fs::File::create(toc_path.with_extension("ucas"))?);

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
        if let Some(path) = path {
            let index = &mut self.toc.directory_index;
            let relative_path = path.strip_prefix(&index.mount_point).with_context(|| format!("mount point {} does not contain path {path}", index.mount_point))?;
            index.add_file(relative_path, self.toc.chunks.len() as u32);
        }

        let mut offset = self.cas_stream.stream_position()?;

        let start_block = self.toc.compression_blocks.len();

        let active_compression = if compress { self.compression_method } else { None };
        // compression_method_index: 0 = None, 1 = first entry in compression_methods vec
        let compression_method_index: u8 = if active_compression.is_some() { 1 } else { 0 };

        let block_size = self.toc.compression_block_size as usize;
        let blocks: Vec<&[u8]> = data.chunks(block_size).collect();
        let level = self.compression_level;

        // Hash the full payload in one pass. blake3 is SIMD-accelerated; faster than
        // per-block update accumulation in practice.
        let hash = blake3::hash(data);

        // Slab compress so the per-chunk scratch is bounded; sized at 2 blocks
        // per worker to amortize rayon dispatch without over-buffering.
        let slab_blocks = rayon::current_num_threads()
            .max(1)
            .saturating_mul(2)
            .min(blocks.len().max(1));

        let mut any_block_compressed = false;
        for slab in blocks.chunks(slab_blocks) {
            let compressed: Vec<(Vec<u8>, u8)> = if let Some(method) = active_compression {
                slab.par_iter()
                    .map(|block| -> Result<(Vec<u8>, u8)> {
                        let mut buf = Vec::new();
                        compression::compress(method, level, block, &mut buf)?;
                        if buf.len() < block.len() {
                            Ok((buf, compression_method_index))
                        } else {
                            Ok((block.to_vec(), 0))
                        }
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                slab.iter().map(|block| (block.to_vec(), 0)).collect()
            };

            for ((written_bytes, actual_method_index), block) in compressed.iter().zip(slab.iter()) {
                let compressed_size = written_bytes.len() as u32;
                let uncompressed_size = block.len() as u32;
                if *actual_method_index != 0 {
                    any_block_compressed = true;
                }
                // Encrypted blocks are stored padded out to the AES block size while the entry
                // keeps the unpadded length, which is what the read path aligns back up.
                let stored_size = match &self.encryption {
                    Some(key) => {
                        use aes::cipher::BlockEncrypt;
                        let mut padded = written_bytes.clone();
                        padded.resize(align_usize(padded.len(), 16), 0);
                        for aes_block in padded.chunks_mut(16) {
                            key.0.encrypt_block(aes_block.into());
                        }
                        self.cas_stream.write_all(&padded)?;
                        padded.len() as u64
                    }
                    None => {
                        self.cas_stream.write_all(written_bytes)?;
                        compressed_size as u64
                    }
                };
                self.toc.compression_blocks.push(FIoStoreTocCompressedBlockEntry::new(offset, compressed_size, uncompressed_size, *actual_method_index));
                offset += stored_size;
            }
        }
        let flags = if any_block_compressed { FIoStoreTocEntryMetaFlags::Compressed } else { FIoStoreTocEntryMetaFlags::empty() };
        let meta = FIoStoreTocEntryMeta {
            chunk_hash: FIoChunkHash::from_blake3(hash.as_bytes()),
            flags,
        };

        let offset_and_length = FIoOffsetAndLength::new(start_block as u64 * self.toc.compression_block_size as u64, data.len() as u64);

        self.toc.chunks.push(chunk_id.with_version(self.toc.version));
        self.toc.chunk_offset_lengths.push(offset_and_length);
        self.toc.chunk_metas.push(meta);

        Ok(())
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
}
