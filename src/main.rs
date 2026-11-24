use sceuf_rs::*;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
