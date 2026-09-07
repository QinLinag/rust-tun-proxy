mod fakeip;
mod tcp;
use std::io::{Read, Write};
use std::println;
use std::net::Ipv4Addr;
use tun2::{Configuration, create};
use tun2::AbstractDevice;   
use etherparse::{Ipv4HeaderSlice, Icmpv4Header, Icmpv4Type, PacketBuilder,IpNumber, UdpHeaderSlice, TcpHeaderSlice};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RData, RecordType, rdata::A};
use log::{info, warn, error};
use std::sync::Arc;
use std::fs::OpenOptions;
use env_logger::{Builder, Env, Target};

use std::collections::HashMap;

//定义我们的fakeip常量
const FAKE_IP_START: Ipv4Addr = Ipv4Addr::new(172, 0, 0, 10); //假设fakeip池从172.0.0.10开始
const FAKE_IP_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0); //假设fakeip池的子网掩码

fn init_logger(path: &str) {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("can not open the log file");

    Builder::from_env(Env::default().default_filter_or("info"))
        .target(Target::Pipe(Box::new(file)))
        .init();
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    init_logger("/tmp/rustVpn.log");
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

    // let mut conns: HashMap<Quad, Conn> = HashMap::new();

    // 1.配置tun
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

    //2. 创建tun设备
    let mut tun = create(&config)?;
    println!("Tun device created successfully.");


    //3.获取设备名称
    println!("Tun device name: {}", tun.tun_name()?);

    let mut buf = [0u8; 65536]; //最大ip包大小
    loop {
        match tun.read(&mut buf) {
            Ok(amount) => {
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
                            tun.write(&out)?;
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
                            tun.write(&out)?;
                        }
                     
                    } else{
                        
                    }

                    if protocol == IpNumber::TCP {  // 如果是tcp报文的话
                        let tcp = TcpHeaderSlice::from_slice(&buf[payload_start..amount])?;
                        let destination_port = tcp.destination_port();
                        let source_port = tcp.source_port();

                        let domain_name = fake_ip_pool.get_domain_from_ip(Ipv4Addr::from_octets(destination));

                        if let Some(domain_name) = domain_name {
                            println!("TCP Query: domain_name = {:?}, destination_port = {:?}, source_port = {:?}", domain_name, destination_port, source_port);
                        }
                    }

                    let version = (buf[0] >> 4) & 0x0F;
                    println!("IP version: {}", version);
                }
            }
            Err(e) => {
                eprintln!("Error reading from tun device: {}", e);
                break;
            }
        }
    }
    Ok(())

}
