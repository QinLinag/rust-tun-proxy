use std::{hash::Hash, net::Ipv4Addr, sync::Arc};
use etherparse::{PacketBuilder, TcpHeaderSlice};
use log::{debug, error, info, warn};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::mpsc};

use crate::{config, fakeip::FakeIpPool, proxy::socks5};


enum Target { //域名代理 or ip代理
    Domain(String),
    Ip(Ipv4Addr),
}

#[derive(Default)]
pub struct Output {
    pub reply: Option<Vec<u8>>,
    pub forward: Option<Vec<u8>>,
    pub close_upstream: bool,
}

pub type Quad = (Ipv4Addr, u16, Ipv4Addr, u16);  //四元组：TCP连接的唯一身份

#[derive(PartialEq)]
pub enum TcpState {  //tcp连接的状态
    SynReceived,
    Established,
    WaitClose,
    FinWait,
    LastAck,
    Closed,
}

pub struct Conn { 
    state: TcpState,
    my_seq: u32,  //我下一个要发的序列号
    my_isn: u32,  //我的初始序列号
    their_seq: u32,
    quad: Quad,  //四元组，唯一标识一个tcp连接
}

impl Conn {
    //收到 SYN: 创建一个连接，同时返回一个 SYN-ACK 包
    pub fn accept(quad: Quad, tcp: &TcpHeaderSlice) -> (Self, Vec<u8>) {
        let my_isn = random_isn();
        let my_seq = my_isn.wrapping_add(1);
        let their_seq = tcp.sequence_number().wrapping_add(1);
        let conn = Conn {
            state: TcpState::SynReceived,
            my_seq,
            my_isn,
            their_seq,
            quad,
        };

        let syn_ack = build_tcp(quad, my_isn, Some(their_seq), Flags {syn: true, ..Default::default()}, &[]);
        (conn, syn_ack)
    }

    //
    pub fn on_packet(&mut self, tcp: &TcpHeaderSlice, payload: &[u8]) -> Option<Vec<u8>> {
        if tcp.rst() { //遇到tcp不正常标准，立刻直接关闭tcp连接
            info!("Received RST for connection: {:?}", self.quad);
            self.state = TcpState::Closed;
            return None;
        }
        match self.state {
            TcpState::SynReceived => {
                // 对方没有收到syn-ack，重传了syn
                if tcp.syn() {
                    let syn_ack = build_tcp(self.quad, self.my_isn, Some(self.their_seq), Flags {syn: true, ..Default::default()}, &[]);
                    return Some(syn_ack);
                }
                // 收到了syn，准备三次握手建立连接
                if tcp.ack() {
                    let expected_ack = self.my_seq;
                    if tcp.acknowledgment_number() != expected_ack {
                        info!("Received TCP packet with incorrect acknowledgment number for connection: {:?}, ack: {:?}, expected: {:?}", self.quad, tcp.acknowledgment_number(), expected_ack);
                        return None;
                    }
                    self.state = TcpState::Established;
                    info!("TCP connection established: {:?}", self.quad);
                }
                None
            }
            TcpState::Established => {
                if self.their_seq != tcp.sequence_number() {  // 期待的不是对方的第一个字节序列号
                    info!("Received TCP packet with incorrect sequence number for connection: {:?}, seq: {:?}, expected: {:?}", self.quad, tcp.sequence_number(), self.their_seq);
                    return Some(build_tcp(self.quad, self.my_seq, Some(self.their_seq), Flags { ..Default::default()}, &[]));  //抛弃内容，然后重新发送期望内容
                }

                if tcp.fin() { //客户端想要关闭连接
                    info!("Received FIN for connection: {:?}", self.quad);
                    self.state = TcpState::WaitClose;
                    let my_this_seq = self.my_seq;  // 当前发送包的第一个字
                    self.their_seq = self.their_seq.wrapping_add(1);  //期待的下一个字节序列号
                    self.my_seq = self.my_seq.wrapping_add(1);  //发送的
                    //直接回复 ack
                    return Some(build_tcp(self.quad, my_this_seq, Some(self.their_seq), Flags {..Default::default()}, &[]));
                }
                if payload.is_empty() {
                    return None;
                }

                let len = payload.len(); 
                info!("[on_packet] Received {:?} bytes, content is: {:?}", len, String::from_utf8_lossy(payload));
                let my_this_ack = self.their_seq;  // 当前对客户端期待的第一个字节序列号
                let my_this_seq = self.my_seq;  // 当前发送包的第一个字
                self.their_seq = self.their_seq.wrapping_add(len as u32);
                
                info!("The Client ACK: {:?}, Client Seq: {:?}, Vpn ACK: {:?}, Vpn Seq: {:?}", tcp.acknowledgment_number(), tcp.sequence_number(), my_this_ack, my_this_seq);

                return Some(build_tcp(self.quad, my_this_seq, Some(self.their_seq), Flags{..Default::default()}, &[]));
            }
            TcpState::LastAck => {
                if tcp.fin() {  // 如果服务端的 fin客户端没有收到， 客户端会重新发送fin
                    info!("Received FIN for connection: {:?} in LastAck state", self.quad);
                    return Some(build_tcp(self.quad, self.my_seq - 1, Some(self.their_seq), Flags {fin: true, ..Default::default()}, &[]));
                }

                if tcp.ack() {
                    if tcp.sequence_number() != self.their_seq {
                        info!("Received TCP packet with incorrect sequence number for connection: {:?}, seq: {:?}, expected: {:?}", self.quad, tcp.sequence_number(), self.their_seq);
                        return None
                    }
                    if tcp.acknowledgment_number() != self.my_seq {
                        info!("Received TCP packet with incorrect acknowledgment number for connection: {:?}, ack: {:?}, expected: {:?}", self.quad, tcp.acknowledgment_number(), self.my_seq);
                        return None
                    }
                    info!("TCP connection closed gracefully: {:?}", self.quad);
                    self.state = TcpState::Closed;
                }
                None
            }
            TcpState::WaitClose => {
                None
            }
            TcpState::FinWait => {
                None
            }
            TcpState::Closed => {
                info!("Received packet for closed connection: {:?}", self.quad);
                None
            }
        }
    }

    // // 挥手就close连接
    // pub fn is_closed(&self) -> bool {

    // }
}

pub async fn conn_task(quad: Quad, mut conn: Conn, mut rx: mpsc::Receiver<Vec<u8>>, write_tx: mpsc::Sender<Vec<u8>>, fake_ip_pool: Arc<FakeIpPool>, app_config: Arc<config::AppConfig>) {
    // 和客户端握手建立链接
    while conn.state != TcpState::Established {
        let pkt = match rx.recv().await {
            Some(p) => p,
            None => return,
        };

        let tcp_header = TcpHeaderSlice::from_slice(&pkt).unwrap(); //tcp头获取
        let tcp_header_len = tcp_header.slice().len(); //tcp头部长度
        let tcp_payload = &pkt[tcp_header_len..];  //tcp payload
        let ret_ack = conn.on_packet(&tcp_header, &tcp_payload);
        if conn.state == TcpState::Closed {
            return ;
        }
        
        match ret_ack {
            Some(ack) => write_tx.send(ack).await.unwrap(),
            None => {
                info!("No response needed for packet in connection: {:?}", quad);
            },
        }   
    }

    //获取fakeip对应的域名
    let(source_ip, source_port, des_ip, des_port) = quad;

    let target = if let Some(domain) = fake_ip_pool.get_domain_from_ip(des_ip) {
        Target::Domain(domain)
    } else {
        if fake_ip_pool.is_fake_ip(des_ip) {
            info!("Supported to get a real ip, but not。 So fake ip and domain are expired");
            //回rst意外中断连接
            let ret_rst = build_tcp(quad, conn.my_seq, Some(conn.their_seq), Flags{rst: true, ..Default::default()}, &[]);
            if write_tx.send(ret_rst).await.is_err() {
                error!("Failed to send RST packet");
                return
            }
            return;
        }
        Target::Ip(des_ip)
    };



    //上游数据chennel
    let (up_tx, up_rx) = mpsc::channel::<Vec::<u8>>(1024);
    let (ret_up_tx, mut ret_up_rx) = mpsc::channel::<Vec::<u8>>(1024);
    let mut up_tx = Some(up_tx);


    //启动一个upstream 上游异步任务
    let config_for_upstream = Arc::clone(&app_config);
    tokio::spawn(on_upstream(quad, target, des_port, up_rx, ret_up_tx, config_for_upstream));

    loop {  //select  要么从tun中读取数据交给上游、要么从上游的channel读取数据交给客户端
        tokio::select! {
            pkt = rx.recv() => { //tun中获取的数据
                let pkt = match pkt {
                    Some(p) => p,
                    None => return
                };
                let tcp_header = TcpHeaderSlice::from_slice(&pkt).unwrap(); //tcp头获取
                let tcp_header_len = tcp_header.slice().len(); //tcp头部长度
                let tcp_payload = &pkt[tcp_header_len..];  //tcp payload

                //回ack给客户端
                let accepted = conn.their_seq == tcp_header.sequence_number(); //顺序不对，先不发送给上游
                let ret_ack = conn.on_packet(&tcp_header, tcp_payload);

                if conn.state == TcpState::Closed {
                    break;
                }

                if let Some(ack) = ret_ack {
                    if write_tx.send(ack).await.is_err() {
                        error!("Failed to send ACK packet");
                        return;
                    }
                }

                if conn.state == TcpState::WaitClose { //客户端发送了fin了
                    continue;
                }

                //将tcp_payload发送给上游
                if accepted && !tcp_payload.is_empty() && !tcp_header.fin() && !tcp_header.rst(){  //客户端的数据必须按顺序获取到 && 客户端没有发送完 && 客户端没有意外
                    info!("[conn_task] send tcp_payload to upstream");
                    if let Some(tx) = &up_tx {
                        if tx.send(tcp_payload.to_vec()).await.is_err() {
                            error!("Failed to send TCP payload to upstream");
                            return;
                        }
                    }
                }
                if tcp_header.fin() { //客户端已经不发送消息了， 上游channel写侧可以关闭了。
                    up_tx = None;
                }
            }
            
            data = ret_up_rx.recv() => { // 上游获取的数据
                let up_stream_data = match data{
                    Some(data) => data,
                    None => return
                };

                // 如果不为空，就构造tcp包发送给tun
                if !up_stream_data.is_empty() {
                    let len = up_stream_data.len();
                    let my_this_seq = conn.my_seq;
                    conn.my_seq = conn.my_seq.wrapping_add(len as u32);
                    let ret_ack = build_tcp(quad, my_this_seq, Some(conn.their_seq), Flags{psh: true, ..Default::default()}, &up_stream_data);
                    
                    if write_tx.send(ret_ack).await.is_err() {
                        error!("Failed to send ACK packet");
                        return;
                    }

                    info!("[conn_task] Recive up stream data and sent to tun, len: {:?}, my seq: {:?}", len, my_this_seq);
                }

            }
        }
        
    }

    //rx被drop了， 消息发送端也会close
}


//异步处理上游数据任务
async fn on_upstream(_quad: Quad, target: Target, des_port: u16, mut up_rx: mpsc::Receiver<Vec::<u8>>, ret_up_tx: mpsc::Sender<Vec::<u8>>, app_config: Arc<config::AppConfig>) -> std::io::Result<()> {
    //建立和上游的连接
    let socks5_target = match target {
        Target::Domain(domain) => socks5::Socks5Target::Domain(domain),
        Target::Ip(ip) => socks5::Socks5Target::Ip(ip),
    };

    let mut tcp_stream: Option<TcpStream> = None;
    match &app_config.proxy {
        config::ProxyConfig::Socks5{address} => {
            if let Ok(stream) = socks5::connect(address,&socks5_target, des_port).await {
                tcp_stream = Some(stream);
            }
        }

        config::ProxyConfig::Shadowsocks{address, method, password} => {

        }
    }
    
    if tcp_stream.is_none() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to establish upstream connection"));
    }
    
    let mut tcp_stream = tcp_stream.unwrap();
    let (mut reader, mut write) = tcp_stream.into_split();
    let mut buf = [0u8; 16 * 1024];

    //循环
    loop {
        tokio::select! {
        //读取要发送给上游的数据
        upstream_data = up_rx.recv() => {
            //判断数据合法性，短路不发送给上游
            match upstream_data {
                Some(data) if !data.is_empty() => {
                    write.write_all(&data).await?;
                }
                Some(_) => {}
                None => break
            }
        }

        //获取上游返回的数据
        upstream_ret_data = reader.read(&mut buf) => {
            //判断数据合法性
            match upstream_ret_data {
                Ok(0) => break, //上有关闭连接
                Ok(n) => {
                    if ret_up_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("[on_upstream] Error reading from upstream: {}", e);
                    return Err(e);
                }
            }
        }
    }
}
    Ok(())
}


#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, Hash)]
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



