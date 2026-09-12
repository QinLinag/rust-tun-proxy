mod fakeip;
mod tcp;
mod logger;
use std::println;
use std::net::Ipv4Addr;
use tokio::io::{AsyncWriteExt, WriteHalf, AsyncReadExt};
use tun2::{AsyncDevice, Configuration};
use tun2::AbstractDevice;   
use etherparse::{Ipv4HeaderSlice, Icmpv4Header, Icmpv4Type, PacketBuilder,IpNumber, UdpHeaderSlice, TcpHeaderSlice};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RData, RecordType, rdata::A};
use log::{info, warn, error};
use std::sync::Arc;
//定义我们的fakeip常量
const FAKE_IP_START: Ipv4Addr = Ipv4Addr::new(172, 0, 0, 10); //假设fakeip池从172.0.0.10开始
const FAKE_IP_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0); //假设fakeip池的子网掩码


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

    //fakeip池
    let fake_ip_pool = Arc::new(fakeip::FakeIpPool::new(FAKE_IP_START,FAKE_IP_MASK));
    //启动清理fakeip的定时任务，
    let cleaner = Arc::clone(&fake_ip_pool);
    std::thread::spawn(move || {
        loop {
            info!("Cleaning expired fake IPs");
            std::thread::sleep(std::time::Duration::from_secs(5));
            cleaner.clean_fake_ip();
        }
    });

    //创建TCP连接池
    let mut tcp_stack = tcp::TcpStack::new();

    //配置tun
    let mut config = Configuration::default();


    config
        .address((172,0,0,1)) //tun 设备的ip
        .netmask((255,255,255,0)) // tun设备的子网掩码
        .destination((172,0,0,2)) // 对端ip
        .up();

    #[cfg(target_os = "linux")]   //linux可能需要root权限
    config.platform_config(|platform_config| {
        platform_config.ensure_root_privileges(true);
    });

    // 创建tun设备
    let dev = tun2::create_as_async(&config)?;
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
    loop {
        let amount = reader.read(&mut buf).await?;
        println!("Read {} bytes from tun device.", amount);

        if amount > 0 {    
            //处理数据
            let ip = Ipv4HeaderSlice::from_slice(&buf[..amount])?; //获取ip头
            let source =ip.source();
            let destination = ip.destination();
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
                if let Some(out) = tcp_stack.on_packet(&ip, &buf[payload_start..amount]) {
                    write_tx.send(out).await?;
                }
            }
            let version = (buf[0] >> 4) & 0x0F;
            println!("IP version: {}", version);
        } else {
        }
    }
}

