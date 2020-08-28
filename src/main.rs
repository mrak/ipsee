extern crate pnet;
extern crate clap;

use std::env;
use std::process::exit;
use std::net::IpAddr;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;

use clap::{App,Arg,ArgMatches};

fn main() {
    let args = parse_args();
    let interface_name = args.value_of("interface").unwrap();
    let interface_name_matcher =
        |interface: &NetworkInterface| interface.name == interface_name;

    let interfaces = datalink::interfaces();
    let interface = match interfaces.into_iter().find(interface_name_matcher) {
        Some(i) => i,
        None => {
            eprint!("No such interface with name \"{}\".", interface_name);
            exit(1);
        }
    };

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("ipsee: unhandled channel type: {}"),
        Err(e) => panic!("ipsee: unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => process_ipv4(&interface_name[..], &ethernet_packet),
                    EtherTypes::Ipv6 => process_ipv6(&interface_name[..], &ethernet_packet),
                    EtherTypes::Arp => process_arp(&interface_name[..], &ethernet_packet),
                    _ => eprintln!("[{}] ? Unknown packet type", interface_name),
                }

            },
            Err(e) => panic!("ipsee: Unable to receive packet: {}", e)
        }
    }
}

fn parse_args<'a>() -> ArgMatches<'a> {
    App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
        .arg(Arg::with_name("interface")
            .help("The interface to listen on")
            .long("interface")
            .short("i")
            .takes_value(true)
            .required(true)
        )
        .get_matches()
}

fn process_ipv4(interface_name: &str, packet: &EthernetPacket) {
    match Ipv4Packet::new(packet.payload()) {
        Some(ipv4_packet) => {
            process_transport(interface_name,
                               IpAddr::V4(ipv4_packet.get_source()),
                               IpAddr::V4(ipv4_packet.get_destination()),
                               ipv4_packet.get_next_level_protocol(),
                               ipv4_packet.payload());
        },
        None => println!("[{}] Malformed IPv4 packet", interface_name)
    }

}

fn process_ipv6(interface_name: &str, packet: &EthernetPacket) {
    match Ipv6Packet::new(packet.payload()) {
        Some(ipv6_packet) => {
            process_transport(interface_name,
                               IpAddr::V6(ipv6_packet.get_source()),
                               IpAddr::V6(ipv6_packet.get_destination()),
                               ipv6_packet.get_next_header(),
                               ipv6_packet.payload());
        },
        None => println!("[{}] Malformed IPv6 packet", interface_name)
    }

}

fn process_arp(interface_name: &str, packet: &EthernetPacket) {
    match ArpPacket::new(packet.payload()) {
        Some(arp_packet) => {
            println!("[{}] A {}({}) > {}({}) ~ operation={:?}",
                     interface_name,
                     packet.get_source(),
                     arp_packet.get_sender_proto_addr(),
                     packet.get_destination(),
                     arp_packet.get_target_proto_addr(),
                     arp_packet.get_operation(),
                     )
        },
        None => println!("[{}] A Malformed packet", interface_name)
    }

}

fn process_transport(interface_name: &str,
                     source: IpAddr,
                     destination: IpAddr,
                     protocol: IpNextHeaderProtocol,
                     packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Tcp => process_tcp(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Udp => process_udp(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Icmp => process_icmp(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Icmpv6 => process_icmpv6(interface_name, source, destination, packet),
        _ => println!("[{}] Unknown packet", interface_name),
    }
}

fn process_tcp(interface_name: &str,
               source: IpAddr,
               destination: IpAddr,
               packet: &[u8]) {
    match TcpPacket::new(packet) {
        Some(tcp_packet) => println!("[{}] T {}:{} > {}:{} ~ {}b",
                                     interface_name,
                                     source,
                                     tcp_packet.get_source(),
                                     destination,
                                     tcp_packet.get_destination(),
                                     packet.len(),
                                     ),
        None => println!("[{}] T Malformed packet", interface_name),
    }
}

fn process_udp(interface_name: &str,
               source: IpAddr,
               destination: IpAddr,
               packet: &[u8]) {
    match UdpPacket::new(packet) {
        Some(udp_packet) => println!("[{}] U {}:{} > {}:{} ~ {}",
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

fn process_icmp(interface_name: &str,
                source: IpAddr,
                destination: IpAddr,
                packet: &[u8]) {
    match IcmpPacket::new(packet) {
        Some(icmp_packet) => {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {}
                _ => println!("[{}] I {} > {}",
                              interface_name,
                              source,
                              destination,
                              )
            }
        }
        None => println!("[{}] I Malformed packet", interface_name),
    }
}

fn process_icmpv6(interface_name: &str,
                  source: IpAddr,
                  destination: IpAddr,
                  packet: &[u8]) {
    match IcmpPacket::new(packet) {
        Some(icmp_packet) => {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {}
                _ => println!("[{}] I {} > {}",
                              interface_name,
                              source,
                              destination,
                              )
            }
        }
        None => println!("[{}] I Malformed packet", interface_name),
    }
}
