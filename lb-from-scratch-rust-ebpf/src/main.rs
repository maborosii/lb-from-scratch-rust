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
use utils::ptr_at_mut;

// Converts a checksum into u16
#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}

#[xdp]
pub fn lb_from_scratch_rust(ctx: XdpContext) -> u32 {
    match try_lb_from_scratch_rust(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lb_from_scratch_rust(ctx: XdpContext) -> Result<u32, ()> {
    let client = Ipv4Addr::new(172, 17, 0, 2);
    let lb = Ipv4Addr::new(172, 17, 0, 3);
    let backend_1 = Ipv4Addr::new(172, 17, 0, 4);
    let backend_2 = Ipv4Addr::new(172, 17, 0, 5);

    let ethhdr_mut = ptr_at_mut::<EthHdr>(&ctx, 0)?;

    match unsafe { (*ethhdr_mut).ether_type } {
        EtherType::Ipv4 => {}
        _ => {
            info!(&ctx, "above ether protocol is not ipv4, pass it");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    unsafe {
        info!(
            &ctx,
            "before eth addr {:x}:{:x}:{:x}:{:x}:{:x}:{:x} -> {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            (*ethhdr_mut).src_addr[0],
            (*ethhdr_mut).src_addr[1],
            (*ethhdr_mut).src_addr[2],
            (*ethhdr_mut).src_addr[3],
            (*ethhdr_mut).src_addr[4],
            (*ethhdr_mut).src_addr[5],
            (*ethhdr_mut).dst_addr[0],
            (*ethhdr_mut).dst_addr[1],
            (*ethhdr_mut).dst_addr[2],
            (*ethhdr_mut).dst_addr[3],
            (*ethhdr_mut).dst_addr[4],
            (*ethhdr_mut).dst_addr[5],
        );
    }

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
                    (*ethhdr_mut).dst_addr[5] = be.octets()[3];
                }
            } else {
                unsafe {
                    (*ipv4hdr_mut).set_dst_addr(client);
                    (*ethhdr_mut).dst_addr[5] = client.octets()[3];
                }
            }
            unsafe {
                (*ipv4hdr_mut).set_src_addr(lb);
                (*ethhdr_mut).src_addr[5] = lb.octets()[3];
            }
        }
        _ => {
            info!(&ctx, "above ether protocol is not tcp, pass it");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    unsafe {
        (*ipv4hdr_mut).check = ipv4_csum::ipv4_checksum_calc(&mut *ipv4hdr_mut).to_be();
    }

    let ip_src_addr = u32::from_be(unsafe { (*ipv4hdr_mut).src_addr });
    let ip_dst_addr = u32::from_be(unsafe { (*ipv4hdr_mut).dst_addr });
    // let mac_src_addr =// Swap src and dst MAC addresses.
    info!(&ctx, "SRC IP: {:i}, DST IP: {:i}", ip_src_addr, ip_dst_addr);
    unsafe {
        info!(
            &ctx,
            "after eth addr {:x}:{:x}:{:x}:{:x}:{:x}:{:x} -> {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            (*ethhdr_mut).src_addr[0],
            (*ethhdr_mut).src_addr[1],
            (*ethhdr_mut).src_addr[2],
            (*ethhdr_mut).src_addr[3],
            (*ethhdr_mut).src_addr[4],
            (*ethhdr_mut).src_addr[5],
            (*ethhdr_mut).dst_addr[0],
            (*ethhdr_mut).dst_addr[1],
            (*ethhdr_mut).dst_addr[2],
            (*ethhdr_mut).dst_addr[3],
            (*ethhdr_mut).dst_addr[4],
            (*ethhdr_mut).dst_addr[5],
        );
    }
    // Ok(xdp_action::XDP_PASS)
    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
