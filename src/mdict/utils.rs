//! Low-level byte reading utilities

use std::io::Read;
use std::error::Error;
use byteorder::{BigEndian, ReadBytesExt};

/// Read a 4 or 8 byte big-endian number.
/// 
/// Used throughout MDict format for size and count fields.
/// Width depends on format version (v1.x uses 4 bytes, v2.x uses 8 bytes).
pub fn read_number(reader: &mut impl Read, number_width: usize) -> Result<u64, Box<dyn Error>> {
    match number_width {
        8 => Ok(reader.read_u64::<BigEndian>()?),
        4 => Ok(reader.read_u32::<BigEndian>()? as u64),
        _ => Err(format!("Invalid number width: {}", number_width).into()),
    }
}

/// Read a 1 or 2 byte big-endian number.
/// 
/// Used for text length prefixes in MDict format.
pub fn read_small_number(reader: &mut impl Read, number_width: usize) -> Result<u64, Box<dyn Error>> {
    match number_width {
        2 => Ok(reader.read_u16::<BigEndian>()? as u64),
        1 => Ok(reader.read_u8()? as u64),
        _ => Err(format!("Invalid small number width: {}", number_width).into()),
    }
}
