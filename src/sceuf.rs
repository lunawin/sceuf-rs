use std::io::{self, Read};

const SCEUF_MAGIC: &[u8; 8] = b"SCEUF\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SceufSegmentTableEntry {
    pub id: u64,
    pub offset: u64,
    pub size: u64,
    pub signing_algorithm: u32,
    pub _padding: [u8; 4],
}

impl SceufSegmentTableEntry {
    pub fn from_reader(reader: &mut impl Read) -> io::Result<Self> {
        let id = read_u64be(reader)?;
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
