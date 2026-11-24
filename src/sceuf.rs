use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::io::{self, Read, Seek, Write};

const SCEUF_MAGIC: &[u8; 8] = b"SCEUF\0\0\0";
pub const PS3_PUP_HMAC_KEY: [u8; 64] = [
    0xF4, 0x91, 0xAD, 0x94, 0xC6, 0x81, 0x10, 0x96, 0x91, 0x5F, 0xD5, 0xD2, 0x44, 0x81, 0xAE, 0xDC,
    0xED, 0xED, 0xBE, 0x6B, 0xE5, 0x13, 0x72, 0x4D, 0xD8, 0xF7, 0xB6, 0x91, 0xE8, 0x8A, 0x38, 0xF4,
    0xB5, 0x16, 0x2B, 0xFB, 0xEC, 0xBE, 0x3A, 0x62, 0x18, 0x5D, 0xD7, 0xC9, 0x4D, 0xA2, 0x22, 0x5A,
    0xDA, 0x3F, 0xBF, 0xCE, 0x55, 0x5B, 0x9E, 0xA9, 0x64, 0x98, 0x29, 0xEB, 0x30, 0xCE, 0x83, 0x66,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentId {
    Version,
    License,
    PromoFlags,
    UpdateFlags,
    PatchBuild,
    Ps3swu,
    Vsh,
    Dots,
    PatchData,
    UpdateFiles,
    SpkgHdr,
    Ps3swu2,
    Unknown(u64),
}

impl SegmentId {
    pub fn filename(self) -> Option<&'static str> {
        match self {
            Self::Version => Some("version.txt"),
            Self::License => Some("license.xml"),
            Self::PromoFlags => Some("promo_flags.txt"),
            Self::UpdateFlags => Some("update_flags.txt"),
            Self::PatchBuild => Some("patch_build.txt"),
            Self::Ps3swu => Some("ps3swu.self"),
            Self::Vsh => Some("vsh.tar"),
            Self::Dots => Some("dots.txt"),
            Self::PatchData => Some("patch_data.pkg"),
            Self::UpdateFiles => Some("update_files.tar"),
            Self::SpkgHdr => Some("spkg_hdr.tar"),
            Self::Ps3swu2 => Some("ps3swu2.self"),
            Self::Unknown(_) => None,
        }
    }

    pub fn as_u64(self) -> u64 {
        match self {
            Self::Version => 0x100,
            Self::License => 0x101,
            Self::PromoFlags => 0x102,
            Self::UpdateFlags => 0x103,
            Self::PatchBuild => 0x104,
            Self::Ps3swu => 0x200,
            Self::Vsh => 0x201,
            Self::Dots => 0x202,
            Self::PatchData => 0x203,
            Self::UpdateFiles => 0x300,
            Self::SpkgHdr => 0x501,
            Self::Ps3swu2 => 0x601,
            Self::Unknown(id) => id,
        }
    }
}

impl From<u64> for SegmentId {
    fn from(id: u64) -> Self {
        match id {
            0x100 => Self::Version,
            0x101 => Self::License,
            0x102 => Self::PromoFlags,
            0x103 => Self::UpdateFlags,
            0x104 => Self::PatchBuild,
            0x200 => Self::Ps3swu,
            0x201 => Self::Vsh,
            0x202 => Self::Dots,
            0x203 => Self::PatchData,
            0x300 => Self::UpdateFiles,
            0x501 => Self::SpkgHdr,
            0x601 => Self::Ps3swu2,
            _ => Self::Unknown(id),
        }
    }
}

impl From<SegmentId> for u64 {
    fn from(id: SegmentId) -> Self {
        id.as_u64()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SceufSegmentTableEntry {
    pub id: SegmentId,
    pub offset: u64,
    pub size: u64,
    pub signing_algorithm: u32,
    pub _padding: [u8; 4],
}

impl SceufSegmentTableEntry {
    pub fn from_reader(reader: &mut impl Read) -> io::Result<Self> {
        let id = SegmentId::from(read_u64be(reader)?);
        let offset = read_u64be(reader)?;
        let size = read_u64be(reader)?;
        let signing_algorithm = read_u32be(reader)?;
        let mut _padding = [0u8; 4];
        reader.read_exact(&mut _padding)?;
        Ok(Self {
            id,
            offset,
            size,
            signing_algorithm,
            _padding,
        })
    }

    pub fn extract_to(
        &self,
        writer: &mut impl Write,
        reader: &mut (impl Read + Seek),
    ) -> io::Result<u64> {
        reader.seek(io::SeekFrom::Start(self.offset))?;
        let mut taken_reader = reader.take(self.size);
        let copied = io::copy(&mut taken_reader, writer)?;
        Ok(copied)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SceufDigestTableEntry {
    pub segment_index: u64,
    pub digest: [u8; 0x14],
    pub _padding: [u8; 4],
}

impl SceufDigestTableEntry {
    pub fn from_reader(reader: &mut impl Read) -> io::Result<Self> {
        let segment_index = read_u64be(reader)?;
        let mut digest = [0u8; 0x14];
        let mut _padding = [0u8; 4];
        reader.read_exact(&mut digest)?;
        reader.read_exact(&mut _padding)?;
        Ok(Self {
            segment_index,
            digest,
            _padding,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SceufHeader {
    pub magic: [u8; 8],
    pub format_version: u64,
    pub image_version: u64,
    pub segment_amount: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub segment_table: Vec<SceufSegmentTableEntry>,
    pub digest_table: Vec<SceufDigestTableEntry>,
    pub digest: [u8; 0x14],
    pub _padding: [u8; 0xC],
}

impl SceufHeader {
    pub fn from_reader(reader: &mut impl Read) -> Result<Self, Box<dyn std::error::Error>> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != SCEUF_MAGIC {
            return Err("Invalid magic.".into());
        }
        let format_version = read_u64be(reader)?;
        let image_version = read_u64be(reader)?;
        let segment_amount = read_u64be(reader)?;
        let file_offset = read_u64be(reader)?;
        let file_size = read_u64be(reader)?;
        let mut segment_tables = Vec::with_capacity(segment_amount.try_into()?);
        let mut digest_tables = Vec::with_capacity(segment_amount.try_into()?);
        let mut digest = [0u8; 0x14];
        let mut _padding = [0u8; 0xC];

        for _ in 0..segment_amount {
            let segment_table = SceufSegmentTableEntry::from_reader(reader)?;
            segment_tables.push(segment_table);
        }

        for _ in 0..segment_amount {
            let digest_table = SceufDigestTableEntry::from_reader(reader)?;
            digest_tables.push(digest_table);
        }

        reader.read_exact(&mut digest)?;
        reader.read_exact(&mut _padding)?;

        Ok(Self {
            magic,
            format_version,
            image_version,
            segment_amount,
            file_offset,
            file_size,
            segment_table: segment_tables,
            digest_table: digest_tables,
            digest,
            _padding,
        })
    }

    pub fn validate_segment(
        &self,
        reader: &mut (impl Read + Seek),
        segment: &SceufSegmentTableEntry,
        digest: &SceufDigestTableEntry,
        key: &[u8],
    ) -> io::Result<bool> {
        if segment.signing_algorithm != 0 {
            return Ok(false);
        }
        reader.seek(io::SeekFrom::Start(segment.offset))?;
        let mut taken = reader.take(segment.size);
        let mut hasher = Hmac::<Sha1>::new_from_slice(key).expect("HMAC excepts any key.");
        let mut remaining = segment.size;

        let mut buf = [0u8; 8192];
        while remaining > 8192 {
            taken.read_exact(&mut buf)?;
            hasher.update(&buf);
            remaining -= 8192;
        }
        let rem = usize::try_from(remaining).expect("<= 1024");
        taken.read_exact(&mut buf[..rem])?;
        hasher.update(&mut buf[..rem]);
        return Ok(hasher.verify_slice(&digest.digest).is_ok());
    }

    pub fn validate(&self, reader: &mut (impl Read + Seek), key: &[u8]) -> io::Result<bool> {
        let mut hasher = Hmac::<Sha1>::new_from_slice(key).expect("HMAC expects any key.");
        reader.seek(io::SeekFrom::Start(0))?;

        let size = 0x30 + (0x40 * self.segment_table.len());
        if u64::try_from(size + 0x20).expect("Invalid size?") != self.file_offset {
            return Ok(false);
        }

        let mut buf = [0u8; 0x10];
        for _ in 0..(size / 0x10) {
            reader.read_exact(&mut buf)?;
            hasher.update(&buf);
        }
        if hasher.verify_slice(&self.digest).is_err() {
            return Ok(false);
        }

        for digest in &self.digest_table {
            let is_valid = self.validate_segment(
                reader,
                &self.segment_table[usize::try_from(digest.segment_index).expect("Invalid size?")],
                digest,
                key,
            )?;
            if !is_valid {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn read_u64be(reader: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

fn read_u32be(reader: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}
