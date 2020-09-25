extern crate clap;
extern crate pnet;

use std::env;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::process::exit;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::vec::Vec;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::ArpOperations;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use clap::{App, Arg, ArgMatches};

fn main() {
    let args = parse_args();
    let (snd, rcv): (Sender<(u32, Vec<u8>)>, Receiver<(u32, Vec<u8>)>) = mpsc::channel();

    capture_packets(&args, snd);
    print_packets(&args, rcv);
}

fn capture_packets(args: &ArgMatches, sender: Sender<(u32, Vec<u8>)>) {
    let interfaces = match args.value_of("interface") {
        None => datalink::interfaces(),
        Some(interface_name) => {
            let interface_name_matcher =
                |interface: &NetworkInterface| interface.name == interface_name;
            datalink::interfaces()
                .into_iter()
                .filter(interface_name_matcher)
                .collect()
        }
    };
    let mut children = Vec::new();

    for interface in interfaces {
        let child_snd = sender.clone();
        let child = thread::spawn(move || {
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("ipsee: unhandled channel type"),
                Err(e) => match e.kind() {
                    ErrorKind::PermissionDenied => {
                        eprintln!(
                            "ipsee: Permission Denied - Unable to open interface {}",
                            interface.name
                        );
                        exit(1)
                    }
                    _ => panic!("ipsee: unable to create channel: {}", e),
                },
            };
            loop {
                match rx.next() {
                    Ok(packet) => child_snd
                        .send((interface.index, packet.to_owned()))
                        .unwrap(),
                    Err(e) => panic!("ipsee: Unable to receive packet: {}", e),
                };
            }
        });
        children.push(child);
    }
}

fn print_packets(_args: &ArgMatches, receiver: Receiver<(u32, Vec<u8>)>) {
    let interfaces = datalink::interfaces();
    loop {
        match receiver.recv() {
            Ok((interface_index, packet)) => {
                // OS interface indexes are 1 based, but Vectors are 0 based
                let index = (interface_index as usize) - 1;
                let ethernet_packet = EthernetPacket::new(packet.as_slice()).unwrap();
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => process_ipv4(&interfaces[index].name[..], &ethernet_packet),
                    EtherTypes::Ipv6 => process_ipv6(&interfaces[index].name[..], &ethernet_packet),
                    EtherTypes::Arp => process_arp(&interfaces[index].name[..], &ethernet_packet),
                    _ => eprintln!("[{}] ? Unknown packet type", interfaces[index].name),
                }
            }
            Err(_) => panic!("All interfaces closed"),
        }
    }
}

fn parse_args<'a>() -> ArgMatches<'a> {
    App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
        .arg(
            Arg::with_name("interface")
                .help("The interface to listen on")
                .long("interface")
                .short("i")
                .takes_value(true),
        )
        .get_matches()
}

fn process_ipv4(interface_name: &str, packet: &EthernetPacket) {
    match Ipv4Packet::new(packet.payload()) {
        Some(ipv4_packet) => {
            process_transport(
                interface_name,
                IpAddr::V4(ipv4_packet.get_source()),
                IpAddr::V4(ipv4_packet.get_destination()),
                ipv4_packet.get_next_level_protocol(),
                ipv4_packet.payload(),
            );
        }
        None => println!("[{}] Malformed IPv4 packet", interface_name),
    }
}

fn process_ipv6(interface_name: &str, packet: &EthernetPacket) {
    match Ipv6Packet::new(packet.payload()) {
        Some(ipv6_packet) => {
            process_transport(
                interface_name,
                IpAddr::V6(ipv6_packet.get_source()),
                IpAddr::V6(ipv6_packet.get_destination()),
                ipv6_packet.get_next_header(),
                ipv6_packet.payload(),
            );
        }
        None => println!("[{}] Malformed IPv6 packet", interface_name),
    }
}

fn process_arp(interface_name: &str, packet: &EthernetPacket) {
    match ArpPacket::new(packet.payload()) {
        Some(arp_packet) => println!(
            "[{}] A {}[{}] > {}[{}] ~ {}",
            interface_name,
            packet.get_source(),
            arp_packet.get_sender_proto_addr(),
            packet.get_destination(),
            arp_packet.get_target_proto_addr(),
            match arp_packet.get_operation() {
                ArpOperations::Reply => "reply",
                ArpOperations::Request => "request",
                _ => "unknown",
            },
        ),
        None => println!("[{}] A Malformed packet", interface_name),
    }
}

fn process_transport(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Tcp => process_tcp(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Udp => process_udp(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Icmp => process_icmp(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Icmpv6 => {
            process_icmpv6(interface_name, source, destination, packet)
        }
        _ => println!("[{}] Unknown packet", interface_name),
    }
}

fn tcp_type_from_flags(flags: u16) -> String {
    if (flags & TcpFlags::RST) != 0 {
        String::from("RST")
    } else if (flags & TcpFlags::FIN) != 0 {
        String::from("FIN")
    } else if (flags & TcpFlags::SYN) != 0 {
        String::from("SYN")
    } else if (flags & TcpFlags::ACK) != 0 {
        String::from("ACK")
    } else {
        String::from("???")
    }
}

fn process_tcp(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    match TcpPacket::new(packet) {
        Some(tcp_packet) => println!(
            "[{}] T {}:{} > {}:{} ~ {} #{} {}b",
            interface_name,
            source,
            tcp_packet.get_source(),
            destination,
            tcp_packet.get_destination(),
            tcp_type_from_flags(tcp_packet.get_flags()),
            tcp_packet.get_sequence(),
            packet.len(),
        ),
        None => println!("[{}] T Malformed packet", interface_name),
    }
}

fn process_udp(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    match UdpPacket::new(packet) {
        Some(udp_packet) => println!(
            "[{}] U {}:{} > {}:{} ~ {}b",
            interface_name,
            source,
            udp_packet.get_source(),
            destination,
            udp_packet.get_destination(),
            udp_packet.get_length(),
        ),
        None => println!("[{}] U Malformed packet", interface_name),
    }
}

fn process_icmp(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    match IcmpPacket::new(packet) {
        Some(icmp_packet) => match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {}
            _ => println!("[{}] I {} > {}", interface_name, source, destination,),
        },
        None => println!("[{}] I Malformed packet", interface_name),
    }
}

fn process_icmpv6(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    match IcmpPacket::new(packet) {
        Some(icmp_packet) => match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {}
            _ => println!("[{}] I {} > {}", interface_name, source, destination,),
        },
        None => println!("[{}] I Malformed packet", interface_name),
    }
}
