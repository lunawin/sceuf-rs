use sceuf_rs::*;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open("PS3UPDAT.PUP")?;

    let header = SceufHeader::from_reader(&mut file)?;
    println!("Format magic is {:?}", header.magic);
    println!("Format version: {}", header.format_version);
    println!("Image version: {}", header.image_version);
    println!("Total segments: {}", header.segment_amount);
    println!("File offset: {}", header.file_offset);
    println!("File size: {}", header.file_size);

    Ok(())
}
