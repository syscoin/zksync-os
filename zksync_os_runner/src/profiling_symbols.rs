use object::{BinaryFormat, CompressionFormat, Object, ObjectSection};
use std::io::{self, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;

// SYSCOIN: Profiling artifacts are local build products; a limit also bounds the initial
// read before the ELF parser inspects section metadata.
const MAX_SYMBOL_BYTES: u64 = 256 * 1024 * 1024;

pub(super) struct ProfilingSymbols {
    file: NamedTempFile,
}

impl ProfilingSymbols {
    pub(super) fn prepare(path: &Path) -> io::Result<Self> {
        let data = read_bounded(path, MAX_SYMBOL_BYTES)?;
        validate(&data)?;

        // The upstream profiler reopens a path later. Give it a private snapshot
        // of the bytes we checked, so replacing the input cannot bypass validation.
        let mut file = NamedTempFile::new()?;
        file.write_all(&data)?;
        file.flush()?;
        let mut permissions = file.as_file().metadata()?.permissions();
        permissions.set_readonly(true);
        file.as_file().set_permissions(permissions)?;
        Ok(Self { file })
    }

    pub(super) fn path(&self) -> &Path {
        self.file.path()
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(invalid("profiling symbols exceed the size limit"));
    }
    Ok(data)
}

fn validate(data: &[u8]) -> io::Result<()> {
    let object = object::File::parse(data)
        .map_err(|error| invalid(format!("invalid profiling symbols: {error}")))?;
    if object.format() != BinaryFormat::Elf || !object.is_little_endian() {
        return Err(invalid("profiling symbols must be a little-endian ELF"));
    }
    for section in object.sections() {
        let name = section
            .name()
            .map_err(|error| invalid(format!("invalid profiling section name: {error}")))?;
        // Upstream intends to reject owned/decompressed DWARF, but does so only
        // after decompression. Inspect metadata without calling that decoder.
        if name.starts_with(".zdebug_") {
            return Err(invalid("compressed profiling sections are not supported"));
        }
        let compression = section
            .compressed_file_range()
            .map_err(|error| invalid(format!("invalid profiling section metadata: {error}")))?;
        if compression.format != CompressionFormat::None {
            return Err(invalid("compressed profiling sections are not supported"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(section_name: &str, flags: u64, payload: &[u8]) -> Vec<u8> {
        let names = format!("\0.shstrtab\0{section_name}\0").into_bytes();
        let data_offset = 64 + 3 * 64;
        let payload_offset = data_offset + names.len();
        let mut data = vec![0; payload_offset + payload.len()];
        data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        data[16..18].copy_from_slice(&1u16.to_le_bytes());
        data[18..20].copy_from_slice(&243u16.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[40..48].copy_from_slice(&64u64.to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes());
        data[58..60].copy_from_slice(&64u16.to_le_bytes());
        data[60..62].copy_from_slice(&3u16.to_le_bytes());
        data[62..64].copy_from_slice(&1u16.to_le_bytes());
        let names_header = 128;
        data[names_header..names_header + 4].copy_from_slice(&1u32.to_le_bytes());
        data[names_header + 4..names_header + 8].copy_from_slice(&3u32.to_le_bytes());
        data[names_header + 24..names_header + 32]
            .copy_from_slice(&(data_offset as u64).to_le_bytes());
        data[names_header + 32..names_header + 40]
            .copy_from_slice(&(names.len() as u64).to_le_bytes());
        let payload_header = 192;
        data[payload_header..payload_header + 4].copy_from_slice(&11u32.to_le_bytes());
        data[payload_header + 4..payload_header + 8].copy_from_slice(&1u32.to_le_bytes());
        data[payload_header + 8..payload_header + 16].copy_from_slice(&flags.to_le_bytes());
        data[payload_header + 24..payload_header + 32]
            .copy_from_slice(&(payload_offset as u64).to_le_bytes());
        data[payload_header + 32..payload_header + 40]
            .copy_from_slice(&(payload.len() as u64).to_le_bytes());
        data[data_offset..payload_offset].copy_from_slice(&names);
        data[payload_offset..].copy_from_slice(payload);
        data
    }

    #[test]
    fn accepts_uncompressed_symbols() {
        validate(&elf(".debug_info", 0, &[0; 16])).unwrap();
    }

    #[test]
    fn rejects_zlib_and_zstd_before_allocating_declared_output() {
        for compression in [1u32, 2] {
            let mut header = [0; 24];
            header[..4].copy_from_slice(&compression.to_le_bytes());
            header[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            header[16..24].copy_from_slice(&1u64.to_le_bytes());
            let error = validate(&elf(".debug_info", 0x800, &header)).unwrap_err();
            assert!(error.to_string().contains("compressed profiling"));
        }
    }

    #[test]
    fn rejects_gnu_compression_without_reading_payload() {
        let error = validate(&elf(".zdebug_info", 0, b"not a compression header")).unwrap_err();
        assert!(error.to_string().contains("compressed profiling"));
    }

    #[test]
    fn rejects_malformed_compression_metadata() {
        assert!(validate(&elf(".debug_info", 0x800, &[])).is_err());
    }

    #[test]
    fn rejects_invalid_and_wrong_endian_objects() {
        assert!(validate(b"not an ELF").is_err());
        let mut bytes = elf(".debug_info", 0, &[]);
        bytes[5] = 2;
        assert!(validate(&bytes).is_err());
    }

    #[test]
    fn bounds_initial_read() {
        let mut source = NamedTempFile::new().unwrap();
        source.write_all(&[0; 17]).unwrap();
        assert!(read_bounded(source.path(), 16).is_err());
        assert_eq!(read_bounded(source.path(), 17).unwrap().len(), 17);
    }

    #[test]
    fn upstream_receives_validated_snapshot_after_input_replacement() {
        let mut source = NamedTempFile::new().unwrap();
        let original = elf(".debug_info", 0, &[0; 16]);
        source.write_all(&original).unwrap();
        let prepared = ProfilingSymbols::prepare(source.path()).unwrap();
        std::fs::write(source.path(), b"replacement").unwrap();
        assert_eq!(std::fs::read(prepared.path()).unwrap(), original);
        assert!(prepared
            .file
            .as_file()
            .metadata()
            .unwrap()
            .permissions()
            .readonly());
    }
}
