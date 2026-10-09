mod fakeip;
mod tcp;
mod logger;
mod proxy;
mod config;
use std::println;
use std::net::Ipv4Addr;
use tokio::io::{AsyncWriteExt, WriteHalf, AsyncReadExt};
use tokio::sync::{mpsc};
use tun2::{AsyncDevice, Configuration};
use tun2::AbstractDevice;   
use etherparse::{Ipv4HeaderSlice, Icmpv4Header, Icmpv4Type, PacketBuilder,IpNumber, UdpHeaderSlice, TcpHeaderSlice};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RData, RecordType, rdata::A};
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::collections::HashMap;

use crate::tcp::Quad;

//写tun的任务
async fn write_tun(mut writer: WriteHalf<AsyncDevice>, mut write_rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    loop {
        match write_rx.recv().await {
            Some(data) => {
                if let Err(e) = writer.write_all(&data).await {
                    error!("Error writing to tun device: {}", e);
                    break;
                }
            }
            None => {
                warn!("Write channel closed");
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    //日志初始化
    logger::init_logger("/tmp/rustVpn.log");
    info!("vpn started!");

    //配置加载
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    let app_config = Arc::new(config::AppConfig::load(&config_path)?);

    //fakeip池
    let fake_ip_pool = Arc::new(fakeip::FakeIpPool::new(app_config.fake_ip.start.parse::<Ipv4Addr>()?, app_config.fake_ip.netmask.parse::<Ipv4Addr>()?, app_config.fake_ip.expire_seconds));
    //启动清理fakeip的定时任务，
    let cleaner = Arc::clone(&fake_ip_pool);
    std::thread::spawn(move || {
        loop {
            debug!("Cleaning expired fake IPs");
            std::thread::sleep(std::time::Duration::from_secs(5));
            cleaner.clean_fake_ip();
        }
    });


    //配置tun
    let mut tun_config = Configuration::default();
    tun_config
        .address((app_config.tun.address.parse::<Ipv4Addr>()?)) //tun 设备的ip
        .netmask((app_config.tun.netmask.parse::<Ipv4Addr>()?)) // tun设备的子网掩码
        .destination((app_config.tun.destination.parse::<Ipv4Addr>()?)) // 对端ip
        .up();

    #[cfg(target_os = "linux")]   //linux可能需要root权限
    tun_config.platform_config(|platform_config| {
        platform_config.ensure_root_privileges(true);
    });

    // 创建tun设备
    let dev = tun2::create_as_async(&tun_config)?;
    println!("Tun device created successfully.");

    //获取设备名称
    println!("Tun device name: {}", dev.tun_name()?);

    let (mut reader, writer) = tokio::io::split(dev); //将tun分成读写两部分
    let (write_tx, write_rx) = tokio::sync::mpsc::channel::<Vec::<u8>>(1024);

    //启动全局唯一写tun的子线程
    tokio::spawn(async move {
        write_tun(writer, write_rx).await;
    });

    let mut buf = vec![0u8; 65536]; //最大ip包大小
    let mut routes: HashMap::<Quad, mpsc::Sender::<Vec::<u8>>> = HashMap::new(); //用于存储tcp连接的路由信息
   
    let mut cleanup_ticker = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        let amount = tokio::select! {
            r = reader.read(&mut buf) => r?,
            _ = cleanup_ticker.tick() => {
                let mut removed_conn: Vec::<Quad> = Vec::new();
                for (quad, tx) in &routes {
                    if tx.is_closed() {
                        removed_conn.push(*quad);
                    }
                }
                for removed_quad in removed_conn {
                    routes.remove(&removed_quad);
                    info!("clean connections, conn is {:?}", removed_quad);
                }
                continue;      
            }
        };
        println!("Read {} bytes from tun device.", amount);

        if amount > 0 {    
            let packet = &&buf[..amount];
            let version = packet[0] >> 4;
            if version != 4 {  //展示只支持ipv4的包
                debug!("Received non-IPv4 packet");
                continue;
            }

            //处理数据
            let ip: Ipv4HeaderSlice<'_> = Ipv4HeaderSlice::from_slice(&buf[..amount])?; //获取ip头
            let source =ip.source();
            let destination = ip.destination();
            let source_ip = Ipv4Addr::from(source);
            let destination_ip = Ipv4Addr::from(destination);
            let protocol = ip.protocol();
            let ttl = ip.ttl();
            println!("Source: {:?}, Destination: {:?}, Protocol: {:?}, TTL: {:?}", source, destination, protocol, ttl);
                    
            let payload_start = ip.slice().len(); //跳过IP头之后的部分，处理icmp头

            // 如果是icmp的话就处理一下
            if protocol == IpNumber::ICMP {
                let (icmp, rest) = Icmpv4Header::from_slice(&buf[payload_start..amount])?;
                
                // 判断是不是 echo request ,同时拿到id/seq
                if let Icmpv4Type::EchoRequest(echo) = icmp.icmp_type {
                    let builder = PacketBuilder::ipv4(
                        destination,
                        source,
                        64
                    ).icmpv4_echo_reply(echo.id, echo.seq);
                    let mut out = Vec::with_capacity(builder.size(rest.len()));
                    builder.write(&mut out, rest)?; // [ip 和 icmp的校验和都在这一步自动计算好]
                    write_tx.send(out).await?;
                }
            }

            // 如果是UDP的话
            if protocol == IpNumber::UDP {
                // 处理udp数据包
                let udp = UdpHeaderSlice::from_slice(&buf[payload_start..amount])?;
                let sourcePort = udp.source_port();
                let destinationPort = udp.destination_port();
                // 如果udp端口是53的话，就是dns
                if destinationPort == 53 {
                    // 处理dns报文
                    let dns_payload_start = payload_start + 8;
                    let dns_payload = &buf[dns_payload_start..amount]; //udp固定头8个字节
                    let req = Message::from_vec(dns_payload)?;
                    let query = req.queries().first().unwrap();
                    let domainName = query.name().clone();   //域名
                    let qtype = query.query_type(); // A /AAAA   

                    println!("DNS Query: domainName = {:?}, qtype = {:?}", domainName, qtype);

                    //构造response
                    let mut resp = Message::new();
                    resp.set_id(req.id())
                        .set_message_type(MessageType::Response)
                        .set_op_code(OpCode::Query)
                        .set_recursion_desired(req.recursion_desired())
                        .set_recursion_available(true)
                        .add_query(query.clone())
                        .set_authoritative(true);

                    // 从fakeip池中获取一个IP， 判断一下是否已经存在了
                    let fake_ip = fake_ip_pool.get_fake_ip(domainName.to_string());

                    if let Some(fake_ip) = fake_ip {
                        if qtype == RecordType::A {
                            resp.add_answer(Record::from_rdata(
                                domainName, 1,
                                RData::A(A(fake_ip))
                            ));
                        }
                    } else {
                    }
                        let resp_bytes = resp.to_vec()?;

                        //套上 UDP + IP 头
                        let builder = PacketBuilder::ipv4(destination, source, 64)
                        .udp(destinationPort, sourcePort);  //ip和端口都要对调

                    let mut out = Vec::new();
                    builder.write(&mut out, &resp_bytes)?;
                    write_tx.send(out).await?;
                }
            } else{

            }

            if protocol == IpNumber::TCP {  // 如果是tcp报文的话
                //刷新一下fakeip和域名时间 todo

                //解析 四元组quad
                let tcp_header_bytes = &buf[payload_start..amount];
                let tcp_header_slice = TcpHeaderSlice::from_slice(tcp_header_bytes)?;
                let source_port = tcp_header_slice.source_port();
                let destination_port = tcp_header_slice.destination_port();
                let quad: Quad = (source_ip, source_port, destination_ip, destination_port);

                match routes.get(&quad) {
                    Some(tx) => { //连接已经有了
                        if tx.send(tcp_header_bytes.to_vec()).await.is_err() {
                            routes.remove(&quad); // 对端已经死了。
                        }
                    }
                    None if tcp_header_slice.syn() => { //握手
                        let (tcp_tx, tcp_rx) = mpsc::channel::<Vec::<u8>>(1024);
                        let (conn, tcp_task) = tcp::Conn::accept(quad, &tcp_header_slice);

                        routes.insert(quad, tcp_tx.clone());
                        let write_tx_clone = write_tx.clone();
                        let fake_ip_pool_clone: Arc<fakeip::FakeIpPool> = Arc::clone(&fake_ip_pool);
                        let config_for_conn: Arc<config::AppConfig> = Arc::clone(&app_config);
                        tokio::spawn(async move {
                            tcp::conn_task(quad, conn, tcp_rx, write_tx_clone, fake_ip_pool_clone, config_for_conn).await;
                        });
                        write_tx.send(tcp_task).await.unwrap();
                        println!("A new tcp connection, quad {:?}", quad);
                    }

                    None => {} //不认识的tcp连接，直接丢弃
                }
                
                
            }
            let version = (buf[0] >> 4) & 0x0F;
            println!("IP version: {}", version);
        } else {
        }
    }
}

