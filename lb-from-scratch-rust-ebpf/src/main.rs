#![no_std]
#![no_main]
mod utils;

use aya_ebpf::{
    bindings::xdp_action, helpers::bpf_ktime_get_ns, macros::xdp, programs::XdpContext,
};
use aya_log_ebpf::info;
use core::net::Ipv4Addr;
use lb_from_scratch_rust_common::ipv4_csum;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use utils::{ptr_at, ptr_at_mut};

#[xdp]
pub fn lb_from_scratch_rust(ctx: XdpContext) -> u32 {
    match try_lb_from_scratch_rust(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lb_from_scratch_rust(ctx: XdpContext) -> Result<u32, ()> {
    // let ip_prefix = Ipv4Addr::new(172, 17, 0, 0);
    let client = Ipv4Addr::new(172, 17, 0, 2);
    let lb = Ipv4Addr::new(172, 17, 0, 3);
    let backend_1 = Ipv4Addr::new(172, 17, 0, 4);
    let backend_2 = Ipv4Addr::new(172, 17, 0, 5);
    let ethhdr = ptr_at::<EthHdr>(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => {
            info!(&ctx, "above ether protocol is not ipv4, pass it");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let ipv4hdr_mut = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    match unsafe { (*ipv4hdr_mut).proto } {
        IpProto::Tcp => {
            if Ipv4Addr::from_bits(u32::from_be(unsafe { (*ipv4hdr_mut).src_addr })) == client {
                let mut be = backend_1;
                if (unsafe { bpf_ktime_get_ns() % 2 } != 0) {
                    be = backend_2;
                }
                unsafe {
                    (*ipv4hdr_mut).set_dst_addr(be);
                    // (*(ipv4hdr as *mut Ipv4Hdr)).dst_addr = be;
                    (*(ethhdr as *mut EthHdr)).dst_addr[5] = be.octets()[3];
                }
            } else {
                unsafe {
                    (*ipv4hdr_mut).set_dst_addr(client);
                    // (*(ipv4hdr as *mut Ipv4Hdr)).dst_addr = client;
                    (*(ethhdr as *mut EthHdr)).dst_addr[5] = client.octets()[3];
                }
            }
            unsafe {
                (*ipv4hdr_mut).set_src_addr(lb);
                // (*(ipv4hdr as *mut Ipv4Hdr)).src_addr = lb;
                (*(ethhdr as *mut EthHdr)).src_addr[5] = lb.octets()[3];
            }
        }
        _ => {
            info!(&ctx, "above ether protocol is not tcp, pass it");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // info!(&ctx, "received a packet");
    unsafe {
        (*ipv4hdr_mut).check = ipv4_csum::ipv4_checksum_calc(&mut *ipv4hdr_mut).to_be();
    }
    let src_addr = u32::from_be(unsafe { (*ipv4hdr_mut).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr_mut).dst_addr });
    info!(&ctx, "SRC IP: {:i}, DST IP: {:i}", src_addr, dst_addr);
    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
