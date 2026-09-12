use std::{collections::HashMap, hash::Hash, net::Ipv4Addr};
use etherparse::{Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use log::{debug, error, info, warn};
use std::time::{SystemTime, UNIX_EPOCH};


pub type Quad = (Ipv4Addr, u16, Ipv4Addr, u16);  //四元组：TCP连接的唯一身份

pub enum TcpState {  //tcp连接的状态
    SynReceived,
    Established,
}

pub struct Conn { 
    state: TcpState,
    my_seq: u32,  //我下一个要发的序列号
    my_isn: u32,  //我的初始序列号
    their_seq: u32,
}

pub struct TcpStack {
    conns: HashMap<Quad, Conn>,
}


impl TcpStack {
    pub fn new() -> Self {
        TcpStack { 
            conns: HashMap::new(),
        }
    }

    pub fn on_packet(&mut self, ip: &Ipv4HeaderSlice, tcp_bytes: &[u8]) -> Option<Vec<u8>> {
        let tcp = match TcpHeaderSlice::from_slice(tcp_bytes) {  //处理header
            Ok(t) => t,
            Err(e) => {error!("Failed to parse TCP header: {}", e); return None;}
        };

        let tcp_hdr_len = tcp.slice().len();  // tcp的header的长度
        let payload = &tcp_bytes[tcp_hdr_len..]; // tcp的payload

        let src = Ipv4Addr::from(ip.source());
        let dst = Ipv4Addr::from(ip.destination());
        let quad: Quad = (src, tcp.source_port(), dst, tcp.destination_port());
        
        info!("Processing TCP packet src: {:?}, src_port: {:?}, dst: {:?}, dst_port: {:?}", src, tcp.source_port(), dst, tcp.destination_port());

        if !self.conns.contains_key(&quad) { //新创建连接
            self.on_new(quad, &tcp)
        } else {  //tcp 连接存在
            self.on_existing(quad, &tcp, payload)
        }
    }

    pub fn on_new(&mut self, quad: Quad, tcp: &TcpHeaderSlice) -> Option<Vec<u8>> {  //tcp连接不存在的情况
       if !(tcp.syn() && !tcp.ack()) {
            debug!("Received TCP packet without SYN flag");
            return None;
       }
       let my_isn = random_isn();  // 获取一个随机的初始序列号

       //计算出这个tcp连接的序列号
       let my_seq = my_isn.wrapping_add(1);   
       let their_seq = tcp.sequence_number().wrapping_add(1);  //对方的syn占用一个序列号，所有要增加1

       self.conns.insert(quad, Conn { state: TcpState::SynReceived, my_seq, my_isn, their_seq });

       info!("New TCP connection established: {:?}", quad);

       Some(build_tcp(quad, my_isn, Some(their_seq), Flags {syn: true, ..Default::default()}, &[]))
    }  

    pub fn on_existing(&mut self, quad: Quad, tcp: &TcpHeaderSlice, payload: &[u8]) -> Option<Vec<u8>> {  //tcp连接已经存在了
        let conn = self.conns.get_mut(&quad)?;

        match conn.state { 
            TcpState::SynReceived => { //tcp连接没有创建完成
                // 情况A: 对方没有收到我的 SYN-ACK， 重传了 SYN       
                if tcp.syn() {
                    info!("Received retransmitted SYN packet for existing connection: {:?}", quad);
                    return Some(build_tcp(quad, conn.my_isn, Some(conn.their_seq), Flags{syn: true, ..Default::default()}, &[]));
                }

                //情况B: 对方收到了SYN-ACK，准备第三次握手
                if tcp.ack() {
                    let expected_seq = conn.my_seq;
                    if tcp.acknowledgment_number() != expected_seq { //对方期望的应该等于我们下一次要发送的
                        info!("Received TCP packet with incorrect acknowledgment number for connection: {:?}, ack: {:?}, expected: {:?}", quad, tcp.acknowledgment_number(), expected_seq);
                        return None;
                    }
                    conn.state = TcpState::Established;
                    info!("TCP connection established: {:?}", quad);
                }
                None
            }

            TcpState::Established => { //tcp连接已经创建好了
                if payload.is_empty() {
                    return None;
                }

                if conn.their_seq != tcp.sequence_number() { //我期望的不等于对方的第一个字节序列号，
                    info!("Received TCP packet with incorrect sequence number for connection: {:?}, seq: {:?}, expected: {:?}", quad, tcp.sequence_number(), conn.their_seq);
                    return Some(build_tcp(quad, conn.my_seq, Some(conn.their_seq), Flags { ..Default::default()}, &[]));  //抛弃内容，然后重新发送期望内容
                }
                let my_this_seq = conn.my_seq; // 当前发送包的第一个字节的序列号
                let my_this_ack = conn.their_seq;  // 当前对客户端期待的第一个字节序列好


                let payload_len = payload.len();
                info!("Received {:?} bytes, content is: {:?}", payload_len, String::from_utf8_lossy(payload));

                conn.their_seq = conn.their_seq.wrapping_add(payload_len as u32);

                conn.my_seq = conn.my_seq.wrapping_add(payload_len as u32);
                info!("The Client ACK: {:?}, Client Seq: {:?}, Vpn ACK: {:?}, Vpn Seq: {:?}", tcp.acknowledgment_number(), tcp.sequence_number(), my_this_ack, my_this_seq);
                return Some(build_tcp(quad, my_this_seq, Some(conn.their_seq), Flags{psh: true, ..Default::default()}, payload));
            }
        }
    }

}

#[derive(Default, Clone, Copy)]
pub struct Flags {
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

//创建tcp回包
fn build_tcp(quad: Quad, seq: u32, ack: Option<u32>, f: Flags, payload: &[u8]) -> Vec<u8> {
    let (their_ip, their_port, my_ip, my_port) = quad;

    let  mut b  = PacketBuilder::ipv4(my_ip.octets(), their_ip.octets(), 64).tcp(my_port, their_port, seq, 65535);

    if f.syn {
        b = b.syn();
    }
    if f.fin {
        b = b.fin();
    }
    if f.rst {
        b = b.rst();
    }
    if f.psh {
        b = b.psh();
    }
    if let Some(a) = ack {
        b = b.ack(a);
    }

    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).expect("build tcp packet");
    out
}


//随机创建一个初始化序列号
fn random_isn() -> u32{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(12345)
}



