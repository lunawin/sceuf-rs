use sceuf_rs::*;
use std::fs::File;
use std::io;
use std::io::Seek;

fn old_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open("PS3UPDAT_v4.93.PUP")?;

    let header = SceufHeader::from_reader(&mut file)?;
    println!("Format magic is {:?}", header.magic);
    println!("Format version: {}", header.format_version);
    println!("Image version: {}", header.image_version);
    println!("Total segments: {}", header.segment_amount);
    println!("File offset: {}", header.file_offset);
    println!("File size: {}", header.file_size);
    println!("==========");

    for segment in &header.segment_table {
        let filename = match segment.id.filename() {
            Some(name) => String::from(name),
            None => format!("unknown_0x{:X}.bin", segment.id.as_u64()),
        };

        let mut to_write = File::create(format!("unpacked_pup/{}", filename))?;
        segment.extract_to(&mut to_write, &mut file)?;
        println!("Exported {}", filename)
    }

    let is_valid = header.validate(&mut file, &PS3_PUP_HMAC_KEY)?;
    println!("Is file valid? {}", is_valid);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut segments = [
        (
            SegmentId::Version,
            &mut File::open("unpacked_pup/version.txt")?,
        ),
        (
            SegmentId::Dots,
            &mut File::open("unpacked_pup/dots.txt")?,
        ),
        (
            SegmentId::License,
            &mut File::open("unpacked_pup/license.xml")?,
        ),
        (
            SegmentId::Ps3swu,
            &mut File::open("unpacked_pup/ps3swu.self")?,
        ),
        (
            SegmentId::Ps3swu2,
            &mut File::open("unpacked_pup/ps3swu2.self")?,
        ),
        (
            SegmentId::SpkgHdr,
            &mut File::open("unpacked_pup/spkg_hdr.tar")?,
        ),
        (
            SegmentId::UpdateFiles,
            &mut File::open("unpacked_pup/update_files.tar")?,
        ),
        (
            SegmentId::UpdateFlags,
            &mut File::open("unpacked_pup/update_flags.txt")?,
        ),
        (SegmentId::Vsh, &mut File::open("unpacked_pup/vsh.tar")?),
    ];
    let mut output = File::options()
        .write(true)
        .truncate(true)
        .read(true)
        .create(true)
        .open("output_ps3updat.pup")?;
    pack(&mut output, &mut segments, [0u8; 8], &PS3_PUP_HMAC_KEY)?;

    output.seek(io::SeekFrom::Start(0))?;
    let header = SceufHeader::from_reader(&mut output)?;
    let valid = header.validate(&mut output, &PS3_PUP_HMAC_KEY)?;

    println!("Repacked PUP is valid? {}", valid);
    Ok(())
}
