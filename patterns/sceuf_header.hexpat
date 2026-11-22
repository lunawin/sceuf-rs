// source: https://www.psdevwiki.com/ps3/Playstation_Update_Package_(PUP)
#pragma endian big
struct SceufSegmentTableEntry {
    u64 id;
    u64 offset;
    u64 size;
    u32 sign_algorithm;
    padding[4];
};

struct SceufDigestTableEntry {
    u64 segment_index;
    u8 digest[0x14];
    padding[4];
};

struct SceufHeader {
    char format_magic[8];
    u64 format_version;
    u64 image_version;
    u64 segment_amount;
    u64 file_offset;
    u64 file_size;
    SceufSegmentTableEntry segment_table[segment_amount];
    SceufDigestTableEntry digest_table[segment_amount];
    u8 digest[0x14];
    padding[0xC];
};

SceufHeader header @ 0x00;