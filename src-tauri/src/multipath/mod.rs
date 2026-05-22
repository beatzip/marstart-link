use std::net::Ipv4Addr;

pub const MAGIC: u16 = 0x4741; // 'GA' (Game Accelerator)

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MultipathHeader {
    pub magic: [u8; 2],
    pub seq: [u8; 4],
    pub src_ip: [u8; 4],
    pub src_port: [u8; 2],
    pub dst_ip: [u8; 4],
    pub dst_port: [u8; 2],
}

impl MultipathHeader {
    pub fn new(seq: u32, src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            magic: MAGIC.to_be_bytes(),
            seq: seq.to_be_bytes(),
            src_ip: src_ip.octets(),
            src_port: src_port.to_be_bytes(),
            dst_ip: dst_ip.octets(),
            dst_port: dst_port.to_be_bytes(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < std::mem::size_of::<Self>() { return None; }
        let magic = u16::from_be_bytes([data[0], data[1]]);
        if magic != MAGIC { return None; }

        Some(Self {
            magic: [data[0], data[1]],
            seq: [data[2], data[3], data[4], data[5]],
            src_ip: [data[6], data[7], data[8], data[9]],
            src_port: [data[10], data[11]],
            dst_ip: [data[12], data[13], data[14], data[15]],
            dst_port: [data[16], data[17]],
        })
    }

    pub fn get_seq(&self) -> u32 { u32::from_be_bytes(self.seq) }
    pub fn get_src_ip(&self) -> Ipv4Addr { Ipv4Addr::from(self.src_ip) }
    pub fn get_dst_ip(&self) -> Ipv4Addr { Ipv4Addr::from(self.dst_ip) }
    pub fn get_src_port(&self) -> u16 { u16::from_be_bytes(self.src_port) }
    pub fn get_dst_port(&self) -> u16 { u16::from_be_bytes(self.dst_port) }
}