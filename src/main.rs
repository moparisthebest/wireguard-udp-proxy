use crate::WgPacket::{Cookie, Data, HandShakeInitiation, HandShakeResponse};

use std::{
    collections::HashMap,
    env,
    io::Result,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    ops::Add,
    sync::RwLock,
    thread,
    time::{Duration, Instant},
};

// https://www.wireguard.com/protocol/
// https://medium.com/asecuritysite-when-bob-met-alice/the-new-way-to-create-a-secure-tunnel-the-wireguard-protocol-89efe954af02

// REJECT-AFTER-TIME from https://www.wireguard.com/papers/wireguard.pdf
//const SESSION_VALID_TIME: Duration = Duration::from_secs(180 * 3);
const SESSION_VALID_TIME: Duration = Duration::from_secs(180);

#[derive(Debug, PartialEq)]
enum WgPacket {
    HandShakeInitiation {
        sender: u32,
    },
    HandShakeResponse {
        #[allow(dead_code)]
        sender: u32,
        receiver: u32,
    },
    Data {
        receiver: u32,
    },
    Cookie {
        receiver: u32,
    },
}

impl WgPacket {
    fn parse(buf: &[u8]) -> Option<WgPacket> {
        let recv = buf.len();
        // smallest packet is cookie which is 10 bytes
        if recv < 10 {
            return None;
        }
        match buf[0] {
            1 => Some(HandShakeInitiation {
                sender: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            }),
            2 => {
                if recv < 12 {
                    None
                } else {
                    Some(HandShakeResponse {
                        sender: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
                        receiver: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
                    })
                }
            }
            3 => Some(Cookie {
                receiver: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            }),
            4 => Some(Data {
                receiver: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            }),
            _ => None,
        }
    }

    fn receiver(&self) -> Option<&u32> {
        match self {
            HandShakeInitiation { .. } => None,
            HandShakeResponse { receiver, .. } => Some(receiver),
            Data { receiver } => Some(receiver),
            Cookie { receiver } => Some(receiver),
        }
    }
}

#[derive(Debug)]
struct ExpiringSocket {
    socket: SocketAddr,
    expires: Instant, // or SystemTime ?
}

impl ExpiringSocket {
    fn new(socket: SocketAddr) -> Self {
        ExpiringSocket {
            socket,
            expires: Instant::now().add(SESSION_VALID_TIME),
        }
    }
}

fn main_single(udp_socket: UdpSocket, target_addr: SocketAddr) -> Result<()> {
    let mut receivers: HashMap<u32, ExpiringSocket> = HashMap::new();

    let mut buf = [0u8; 2048];
    loop {
        let (recv, src_addr) = udp_socket.recv_from(&mut buf)?;

        //println!("udp got len: {} from src_addr: {}", recv, src_addr);

        let buf = &buf[..recv];

        let packet = match WgPacket::parse(buf) {
            None => continue, // ignore invalid packets
            Some(p) => p,
        };

        //println!("valid {:?}", packet);

        let to_addr = if src_addr == target_addr {
            // target isn't allowed to initiate
            match packet
                .receiver()
                .and_then(|receiver| receivers.get(receiver))
            {
                Some(to_addr) => &to_addr.socket,
                None => continue,
            }
        } else {
            match packet {
                HandShakeInitiation { sender } => {
                    // we are going to expire things now todo: only after SESSION_TIME elapsed?
                    let now = Instant::now();
                    //println!("retaining now: {:?}, before: {:?}", now, receivers);
                    receivers.retain(|_, expiring_socket| expiring_socket.expires > now);
                    //println!("retaining now: {:?}, after: {:?}", now, receivers);

                    receivers.insert(sender, ExpiringSocket::new(src_addr));
                }
                HandShakeResponse { .. } => continue, // only target is allowed to respond to a handshake
                _ => {}
            }
            // otherwise it's always the target
            &target_addr
        };

        //println!("sending to: {}", to_addr);
        //println!("receivers: {:?}", receivers);

        // now reply back to src_addr to make sure other direction works
        let sent = udp_socket.send_to(buf, &to_addr)?;
        assert_eq!(sent, recv);
    }
}

fn main_threaded(
    udp_socket: UdpSocket,
    target_addr: SocketAddr,
    thread_count: usize,
) -> Result<()> {
    let udp_socket = Box::leak(Box::new(udp_socket));

    let receivers: &mut RwLock<HashMap<u32, ExpiringSocket>> =
        Box::leak(Box::new(RwLock::new(HashMap::new())));

    let mut threads = Vec::with_capacity(thread_count);
    for _id in 0..thread_count {
        let udp_socket = &*udp_socket;
        let receivers = &*receivers;
        threads.push(thread::spawn::<_, Result<()>>(move || {
            let mut buf = [0u8; 2048];
            loop {
                let (recv, src_addr) = udp_socket.recv_from(&mut buf)?;

                //println!("{}: udp got len: {} from src_addr: {}", id, recv, src_addr);

                let buf = &buf[..recv];

                let packet = match WgPacket::parse(buf) {
                    None => continue, // ignore invalid packets
                    Some(p) => p,
                };

                //println!("{}: valid {:?}", id, packet);

                let to_addr: SocketAddr = if src_addr == target_addr {
                    // target isn't allowed to initiate
                    match packet.receiver().and_then(|receiver| {
                        receivers.read().unwrap().get(receiver).map(|s| s.socket)
                    }) {
                        Some(to_addr) => to_addr,
                        None => continue,
                    }
                } else {
                    match packet {
                        HandShakeInitiation { sender } => {
                            // we are going to expire things now
                            let now = Instant::now();
                            let mut receivers = receivers.write().unwrap();
                            //println!("retaining now: {:?}, before: {:?}", now, receivers);
                            receivers.retain(|_, expiring_socket| expiring_socket.expires > now);
                            //println!("retaining now: {:?}, after: {:?}", now, receivers);

                            receivers.insert(sender, ExpiringSocket::new(src_addr));
                        }
                        HandShakeResponse { .. } => continue, // only target is allowed to respond to a handshake
                        _ => {}
                    }
                    // otherwise it's always the target
                    target_addr
                };

                //println!("{}: sending to: {}", id, to_addr);
                //println!("{}: receivers: {:?}", id, receivers.read().unwrap());

                // now reply back to src_addr to make sure other direction works
                let sent = udp_socket.send_to(buf, &to_addr)?;
                assert_eq!(sent, recv);
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap()?;
    }
    Ok(())
}

fn main() -> Result<()> {
    //println!("starting...");
    let mut args = env::args().skip(1);
    let target_addr = match args.next() {
        None => {
            eprintln!("usage: wireguard-udp-proxy target_addr [bind_addr default: 0.0.0.0:5678] [num_threads default: 1]");
            return Ok(()); // todo: exit code?
        }
        Some(target_addr) => target_addr
            .to_socket_addrs()?
            .next()
            .expect("invalid target_addr"),
    };
    let bind_addr = args.next().unwrap_or_else(|| "0.0.0.0:5678".to_string());
    let thread_count: usize = args
        .next()
        .unwrap_or_else(|| "1".to_string())
        .parse()
        .unwrap();

    let udp_socket = UdpSocket::bind(bind_addr)?;
    if thread_count == 1 {
        main_single(udp_socket, target_addr)
    } else {
        main_threaded(udp_socket, target_addr, thread_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_parse() {
        let sender = 3927566598u32;
        let sender_bytes = sender.to_le_bytes();
        let receiver = 350987235u32;
        let receiver_bytes = receiver.to_le_bytes();

        let packet = [
            1,
            0,
            0,
            0,
            sender_bytes[0],
            sender_bytes[1],
            sender_bytes[2],
            sender_bytes[3],
            0,
            0,
        ];
        assert_eq!(
            WgPacket::parse(&packet),
            Some(HandShakeInitiation { sender })
        );

        let packet = [
            2,
            0,
            0,
            0,
            sender_bytes[0],
            sender_bytes[1],
            sender_bytes[2],
            sender_bytes[3],
            receiver_bytes[0],
            receiver_bytes[1],
            receiver_bytes[2],
            receiver_bytes[3],
            0,
            0,
        ];
        assert_eq!(
            WgPacket::parse(&packet),
            Some(HandShakeResponse { sender, receiver })
        );

        let packet = [
            3,
            0,
            0,
            0,
            receiver_bytes[0],
            receiver_bytes[1],
            receiver_bytes[2],
            receiver_bytes[3],
            0,
            0,
        ];
        assert_eq!(WgPacket::parse(&packet), Some(Cookie { receiver }));

        let packet = [
            4,
            0,
            0,
            0,
            receiver_bytes[0],
            receiver_bytes[1],
            receiver_bytes[2],
            receiver_bytes[3],
            0,
            0,
        ];
        assert_eq!(WgPacket::parse(&packet), Some(Data { receiver }));
    }
}
