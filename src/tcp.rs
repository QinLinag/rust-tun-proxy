use std::net::Ipv4Addr;

type Quad = (Ipv4Addr, u16, Ipv4Addr, u16);  //四元组：TCP连接的唯一身份

enum TcpState {  //tcp连接的状态
    SynReceived,
    Established,
}

struct Conn { 
    state: TcpState,
    my_seq: u32,
    their_seq: u32,
}