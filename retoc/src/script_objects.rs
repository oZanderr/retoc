use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};

use anyhow::Result;
use serde::Serializer;
use strum::FromRepr;
use tracing::instrument;

use crate::name_map::{EMappedNameType, read_name_batch_parts};
use crate::{
    name_map::{FMappedName, FNameMap},
    ser::*,
};

#[derive(Debug, Clone, Default)]
pub struct ZenScriptObjects {
    pub global_name_map: FNameMap,
    pub script_objects: Vec<FScriptObjectEntry>,
    pub script_object_lookup: HashMap<FPackageObjectIndex, FScriptObjectEntry>,
}
impl ZenScriptObjects {
    #[instrument(skip_all, name = "ZenScriptObjects")]
    pub fn deserialize_new<S: Read>(s: &mut S) -> Result<Self> {
        let global_name_map: FNameMap = FNameMap::deserialize(s, EMappedNameType::Global)?;
        Ok(Self::new(s.de()?, global_name_map))
    }
    #[instrument(skip_all, name = "ZenScriptObjects")]
    pub fn deserialize_old<S: Read>(s: &mut S, names: &[u8]) -> Result<Self> {
        let global_name_map: FNameMap = FNameMap::create_from_names(EMappedNameType::Global, read_name_batch_parts(names)?);
        Ok(Self::new(s.de()?, global_name_map))
    }
    #[instrument(skip_all, name = "ZenScriptObjects")]
    pub fn serialize_new<S: Write>(&self, s: &mut S) -> Result<()> {
        self.global_name_map.serialize(s)?;
        s.ser(&self.script_objects)?;
        Ok(())
    }
    /// An empty table with a global name map, for building one from paths alone.
    pub fn create_empty() -> Self {
        Self::new(Vec::new(), FNameMap::create(EMappedNameType::Global))
    }
    /// Adds an entry for every object path the table lacks, following the gen-script-objects
    /// convention: `/Script/Pkg` keeps its full path as the name with a null outer; anything deeper
    /// keeps its leaf name under its outer. Missing outers are added too, and a `Default__X`
    /// directly under a package is given `Pkg.X` as its CDO class so that class is labelled as one.
    /// Returns how many entries were added.
    pub fn extend_with_paths<'p>(&mut self, paths: impl IntoIterator<Item = &'p str>) -> usize {
        let before = self.script_objects.len();
        for path in paths {
            self.add_path(path);
        }
        self.script_objects.len() - before
    }
    fn add_path(&mut self, path: &str) -> bool {
        let global_index = FPackageObjectIndex::create_script_import(path);
        if self.script_object_lookup.contains_key(&global_index) {
            return false;
        }
        let (name, outer_index, cdo_class_index) = match path.rfind(['.', ':']) {
            None => (path, FPackageObjectIndex::create_null(), FPackageObjectIndex::create_null()),
            Some(split) => {
                let (outer, name) = (&path[..split], &path[split + 1..]);
                self.add_path(outer);
                let outer_is_package = !outer.contains(['.', ':']);
                let cdo_class_index = match name.strip_prefix("Default__") {
                    Some(class) if outer_is_package => {
                        let class_path = format!("{outer}.{class}");
                        self.add_path(&class_path);
                        FPackageObjectIndex::create_script_import(&class_path)
                    }
                    _ => FPackageObjectIndex::create_null(),
                };
                (name, FPackageObjectIndex::create_script_import(outer), cdo_class_index)
            }
        };
        let entry = FScriptObjectEntry {
            object_name: self.global_name_map.store(name),
            global_index,
            outer_index,
            cdo_class_index,
        };
        self.script_objects.push(entry);
        self.script_object_lookup.insert(global_index, entry);
        true
    }
    fn new(script_objects: Vec<FScriptObjectEntry>, global_name_map: FNameMap) -> Self {
        // Build lookup by package object index for fast access
        let mut script_object_lookup: HashMap<FPackageObjectIndex, FScriptObjectEntry> = HashMap::with_capacity(script_objects.len());
        script_objects.iter().for_each(|script_object| {
            script_object_lookup.insert(script_object.global_index, *script_object);
        });
        Self { global_name_map, script_objects, script_object_lookup }
    }
    pub fn print(&self) {
        for s in &self.script_objects {
            println!("{}:", self.global_name_map.get(s.object_name));
            println!("  global_index:    {:?}", s.global_index.value());
            println!("  outer_index:     {:?}", s.outer_index.value());
            println!("  cdo_class_index: {:?}", s.cdo_class_index.value());
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct FScriptObjectEntry {
    pub object_name: FMappedName,
    pub global_index: FPackageObjectIndex,
    pub outer_index: FPackageObjectIndex,
    pub cdo_class_index: FPackageObjectIndex,
}
impl Readable for FScriptObjectEntry {
    #[instrument(skip_all, name = "FScriptObjectEntry")]
    fn de<S: Read>(s: &mut S) -> Result<Self> {
        Ok(Self {
            object_name: s.de()?,
            global_index: s.de()?,
            outer_index: s.de()?,
            cdo_class_index: s.de()?,
        })
    }
}
impl Writeable for FScriptObjectEntry {
    #[instrument(skip_all, name = "FScriptObjectEntry")]
    fn ser<S: Write>(&self, s: &mut S) -> Result<()> {
        s.ser(&self.object_name)?;
        s.ser(&self.global_index)?;
        s.ser(&self.outer_index)?;
        s.ser(&self.cdo_class_index)?;
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
#[repr(C)] // Needed for sizeof to determine number of entries in package header
pub struct FPackageObjectIndex {
    type_and_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, FromRepr)]
pub enum FPackageObjectIndexType {
    Export,
    ScriptImport,
    PackageImport,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct FPackageImportReference {
    pub imported_package_index: u32,
    pub imported_public_export_hash_index: u32,
}

impl FPackageObjectIndex {
    const INDEX_BITS: u64 = 62;
    const INDEX_MASK: u64 = (1 << Self::INDEX_BITS) - 1;
    const TYPE_SHIFT: u64 = Self::INDEX_BITS;
    const INVALID_ID: u64 = !0;

    pub fn create_from_raw(raw: u64) -> Self {
        Self { type_and_id: raw }
    }
    pub fn create(kind: FPackageObjectIndexType, value: u64) -> Self {
        Self {
            type_and_id: ((kind as u64) << Self::TYPE_SHIFT) | value,
        }
    }
    pub fn create_null() -> Self {
        Self::create(FPackageObjectIndexType::Null, Self::INVALID_ID)
    }
    pub fn create_export(export_index: u32) -> Self {
        Self::create(FPackageObjectIndexType::Export, export_index as u64)
    }
    pub fn create_script_import(object_path: &str) -> Self {
        let import_hash = Self::generate_import_hash_from_object_path(object_path);
        Self::create(FPackageObjectIndexType::ScriptImport, import_hash)
    }
    pub fn create_package_import(import_ref: FPackageImportReference) -> Self {
        let import_value = import_ref.imported_public_export_hash_index as u64 | ((import_ref.imported_package_index as u64) << 32);
        Self::create(FPackageObjectIndexType::PackageImport, import_value)
    }
    pub fn create_script_import_from_verse_path(verse_path: &str) -> Self {
        let import_hash = Self::generate_import_hash_from_verse_path(verse_path);
        Self::create(FPackageObjectIndexType::ScriptImport, import_hash)
    }
    // Function to create a legacy UE4 zen package import from the full, lower-case name of the imported/exported object using / as a separator
    pub fn create_legacy_package_import_from_path(object_path: &str) -> Self {
        let import_hash = Self::generate_import_hash_from_object_path(object_path);
        Self::create(FPackageObjectIndexType::PackageImport, import_hash)
    }
    pub fn raw_index(self) -> u64 {
        self.type_and_id & Self::INDEX_MASK
    }
    pub fn kind(self) -> FPackageObjectIndexType {
        FPackageObjectIndexType::from_repr((self.type_and_id >> Self::TYPE_SHIFT) as usize).unwrap()
    }
    pub fn value(self) -> Option<u64> {
        (self.kind() != FPackageObjectIndexType::Null).then_some(self.type_and_id)
    }
    pub fn export(self) -> Option<u32> {
        (self.kind() == FPackageObjectIndexType::Export).then_some(self.type_and_id as u32)
    }
    pub fn package_import(self) -> Option<FPackageImportReference> {
        (self.kind() == FPackageObjectIndexType::PackageImport).then_some(FPackageImportReference {
            imported_package_index: ((self.type_and_id & FPackageObjectIndex::INDEX_MASK) >> 32) as u32,
            imported_public_export_hash_index: (self.type_and_id as u32),
        })
    }
    pub fn is_null(self) -> bool {
        self.kind() == FPackageObjectIndexType::Null
    }
    pub fn to_raw(self) -> u64 {
        self.type_and_id
    }

    fn generate_import_hash_from_object_path(object_path: &str) -> u64 {
        let lower_slash_path = object_path
            .chars()
            .map(|c| match c {
                ':' | '.' => '/',
                c => c.to_ascii_lowercase(),
            })
            .collect::<String>();
        let mut hash: u64 = cityhasher::hash(lower_slash_path.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>());
        hash &= !(3 << 62);
        hash
    }
    fn generate_import_hash_from_verse_path(verse_path: &str) -> u64 {
        let mut hash: u64 = cityhasher::hash(verse_path.as_bytes());
        hash &= !(3 << 62);
        hash
    }
}
impl Readable for FPackageObjectIndex {
    #[instrument(skip_all, name = "FPackageObjectIndex")]
    fn de<S: Read>(s: &mut S) -> Result<Self> {
        Ok(Self { type_and_id: s.de()? })
    }
}
impl Display for FPackageObjectIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.serialize_u64(self.type_and_id)
    }
}
impl Writeable for FPackageObjectIndex {
    #[instrument(skip_all, name = "FPackageObjectIndex")]
    fn ser<S: Write>(&self, s: &mut S) -> Result<()> {
        s.ser(&self.type_and_id)?;
        Ok(())
    }
}
impl std::fmt::Debug for FPackageObjectIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.kind() {
            FPackageObjectIndexType::Export => write!(f, "FPackageObjectIndex::Export({:X?})", self.export().unwrap()),
            FPackageObjectIndexType::ScriptImport => write!(f, "FPackageObjectIndex::ScriptImport({:X?})", self.raw_index()),
            FPackageObjectIndexType::PackageImport => write!(f, "FPackageObjectIndex::PackageImport({:X?})", self.package_import().unwrap()),
            FPackageObjectIndexType::Null => write!(f, "FPackageObjectIndex::Null"),
        }
    }
}

#[cfg(test)]
mod test {
    use fs_err as fs;
    use std::io::BufReader;

    use super::*;

    #[test]
    fn extending_with_paths_synthesises_outers_and_known_hashes() {
        let mut table = ZenScriptObjects::create_empty();
        let added = table.extend_with_paths(["/Script/NePatchUtility.NePatchUtility:MountPak", "/Script/NePatchUtility.Default__NePatchUtility"]);
        assert_eq!(added, 4);

        let package = FPackageObjectIndex::create_from_raw(0x6b97a5a0579ae351);
        let class = FPackageObjectIndex::create_from_raw(0x71515cdfe40c0987);
        let mount_pak = FPackageObjectIndex::create_from_raw(0x46a3791039776701);
        let package_entry = table.script_object_lookup[&package];
        assert!(package_entry.outer_index.is_null());
        assert_eq!(table.global_name_map.get(package_entry.object_name), "/Script/NePatchUtility");
        let class_entry = table.script_object_lookup[&class];
        assert_eq!(class_entry.outer_index, package);
        assert_eq!(table.global_name_map.get(class_entry.object_name), "NePatchUtility");
        assert!(class_entry.cdo_class_index.is_null());
        let function_entry = table.script_object_lookup[&mount_pak];
        assert_eq!(function_entry.outer_index, class);
        assert_eq!(table.global_name_map.get(function_entry.object_name), "MountPak");
        let cdo_entry = table.script_object_lookup[&FPackageObjectIndex::create_script_import("/Script/NePatchUtility.Default__NePatchUtility")];
        assert_eq!(cdo_entry.outer_index, package);
        assert_eq!(cdo_entry.cdo_class_index, class);

        assert_eq!(table.extend_with_paths(["/Script/NePatchUtility", "/Script/NePatchUtility.NePatchUtility:MountPak"]), 0);
        assert_eq!(table.script_objects.len(), 4);
    }

    #[test]
    fn known_native_paths_hash_to_the_verified_indices() {
        for (path, raw) in [
            ("/Script/NePatchUtility.NePatchUtility:UnmountPak", 0x4916536cbd4ab90bu64),
            ("/Script/NePatchUtility.NePatchUtility:GetMountedPakNames", 0x73341021be7e0692),
            ("/Script/NePatchUtility.NePatchUtility:GetHashFilePaths", 0x5885104175ce022b),
            ("/Script/NePatchUtility.NePatchUtility:GetUtocEntryInfos", 0x73c7dddf3f70cac5),
        ] {
            assert_eq!(FPackageObjectIndex::create_script_import(path).to_raw(), raw, "{path}");
        }
    }

    #[test]
    fn test_read_script_objects_new() -> Result<()> {
        let mut stream = BufReader::new(fs::File::open("tests/UE5.3/ScriptObjects.bin")?);

        let _script_objects = ZenScriptObjects::deserialize_new(&mut stream)?;
        // script_objects.print();

        Ok(())
    }

    #[test]
    fn test_read_script_objects_old() -> Result<()> {
        let names = fs::read("tests/UE4.27/LoaderGlobalNames_1.bin")?;
        let mut meta = BufReader::new(fs::File::open("tests/UE4.27/LoaderInitialLoadMeta_1.bin")?);

        let _script_objects = ZenScriptObjects::deserialize_old(&mut meta, &names)?;
        // script_objects.print();

        Ok(())
    }
}
