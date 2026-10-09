
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream};
use std::format;
use std::io::{Result, Error, ErrorKind};
use std::net::{Ipv4Addr};
use log::{info, warn, error};
const SOCKS5_ADDR: &str = "127.0.0.1:1080";

pub enum Socks5Target { //socks5 支持代理ipv4/域名
    Domain(String),
    Ip(Ipv4Addr),
}



pub async fn connect(upstream_address: &str,target: &Socks5Target, port: u16) -> Result<TcpStream> {
    let mut s = TcpStream::connect(upstream_address).await?;
    negotiate_auth(&mut s).await?;
    send_request(&mut s, target, port).await?;
    Ok(s)
}   

async fn negotiate_auth(tcp_stream: &mut TcpStream) -> Result<()>{
    tcp_stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut resp = [0u8; 2];
    tcp_stream.read_exact(&mut resp).await?;

    if resp[0] != 0x05{ //对方不是socks5
        warn!("upstream is not surpported socks5 protocol!");
        return Err(Error::new(ErrorKind::InvalidData, format!("upstream is not surpported socks5 protocal!")));
    }


    if resp[1] != 0x00 { //上游不选择我们支持的无需认证方式
        if resp[1] == 0xFF { // 都不接受
            warn!("upstream reject our all socks5 connect way!");
        }
        return Err(Error::new(ErrorKind::InvalidData, format!("socks5 negotiate failed, method={:#04x}", resp[1])));
    }

    Ok(())
}

async fn send_request(tcp_stream: &mut TcpStream, target: &Socks5Target, port: u16) -> Result<()> {
    let mut data: Vec<u8> = Vec::new();

    data.push(0x05); //VER:
    data.push(0x01); //CMD:
    data.push(0x00); //RSV

    match target{
        Socks5Target::Domain(domain) => { //代理域名
            if domain.as_bytes().len() >= u8::MAX as usize { //socks5中，代理域名只有一个字节长度存放
                return Err(Error::new(ErrorKind::InvalidData, format!("invali domain name!")));
            }
            data.push(0x03); //ATYP: 表示代理的域名
            data.push(domain.len() as u8); //域名长度追加
            data.extend_from_slice(domain.as_bytes()); //域名追加
        }

        Socks5Target::Ip(ip) => { //代理ip
            data.push(0x01); //ATYP: 表示代理的Ipv4
            data.extend_from_slice(&ip.octets());
        }

        //其实还有一种代理Ipv6
    }

    data.extend_from_slice(&port.to_be_bytes()); // to_be_bytes 是转成大端的方式，  网络常用大端

    tcp_stream.write_all(&data).await?;

    let mut resp = [0u8; 4];  // 读取固定的数据
    tcp_stream.read_exact(& mut resp).await?;

    if resp[0] != 0x05 {
        warn!("upstream is not surpported socks5 protocol!");
        return Err(Error::new(ErrorKind::InvalidData, format!("upstream is not surpported socks5 protocal!")));
    }

    if resp[1] != 0x00 { //只有0x00才表示为成功
        error!("socks5 request failed, reply={:#04x}", resp[1]);
        return Err(Error::new(ErrorKind::InvalidData, format!("socks5 request failed, reply={:#04x}", resp[1])));
    }

    match resp[3] { //根据ATYP将剩余的数据读走
        0x01 => { 
            //ipv4 地址四个字节
            let mut addr = [0u8; 4];
            tcp_stream.read_exact(&mut addr).await?;
        }

        0x03 => {
            //域名： 先读取长度，再读取域名
            let mut len = [0u8; 1];
            tcp_stream.read_exact(&mut len).await?;

            let mut domain = vec![0u8; len[0] as usize];
            tcp_stream.read_exact(&mut domain).await?;
        }

        0x04 => {
            //ipv6 地址16个字节
            let mut addr = [0u8; 16];
            tcp_stream.read_exact(&mut addr).await?;
        }

        _ => {
            return Err(Error::new(ErrorKind::InvalidData, "Unsupported ATYP"));
        }
    }

    //所有类型最后都有两个字节的端口
    let mut port = [0u8; 2];
    tcp_stream.read_exact(&mut port).await?;
    
    Ok(())
}
