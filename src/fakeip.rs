use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::sync::{RwLock, Arc};
use log::{info, warn, error};
use std::time::Instant;
pub struct FakeIp {
    ip: Ipv4Addr,
    lastTimeUsed: Instant, //剩余时间，单位秒,  每次使用就会更新
}

pub struct FakeIpPool {
    inner: RwLock<FakeIpPoolInner>,  // 用于保护fakeIp池的并发访问
}


impl FakeIpPool {
    pub fn new(start: Ipv4Addr, fakeIpMask: Ipv4Addr) -> Self {
        let inner = FakeIpPoolInner::new(start, fakeIpMask);
        Self {
            inner: RwLock::new(inner),
        }
    }

    pub fn clean_fake_ip(&self) {
        if let Ok(mut inner) = self.inner.write() {
            info!("Start to clean expired fake IPs");
            inner.cleanFakeIp();
        }
    }

    pub fn get_fake_ip(&self, domain: String) -> Option<Ipv4Addr> {
        if let Ok(mut inner) = self.inner.write() {
            return inner.getFakeIp(domain);
        }
        None
    }

    pub fn get_domain_from_ip(&self, ip: Ipv4Addr) -> Option<String> {
        if let Ok(inner) = self.inner.read() {
            return inner.fakeIpToDomain(ip);
        }
        None
    }
}

pub struct FakeIpPoolInner {
    startIp: Ipv4Addr, //起始fakeIp
    lastIp: Ipv4Addr, //最后一个fakeIp

    fakeIpMask: Ipv4Addr, //fakeIp子网掩码
    
    expireTime: u64, //fakeIp过期时间，单位秒   
    
    availableIps: Vec<Ipv4Addr>, //可用的fakeIp列表


    ip_to_domain: HashMap<Ipv4Addr, String>, //fakeIp对应的域名映射
    domain_to_ip: HashMap<String, FakeIp>, //域名对应的fakeIp映射
}





impl FakeIpPoolInner {
    pub fn new(start: Ipv4Addr, fakeIpMask: Ipv4Addr) -> Self {
        info!("Initializing FakeIpPoolInner with start IP: {:?} and mask: {:?}", start, fakeIpMask);
        //计算可用的fakeip数、第一个可用fakeip、下一个可用fakeip
        let startIpInt = start.to_bits();
        let maskIpInt =  fakeIpMask.to_bits();
        //1.计算网络地址
        let networkInt = startIpInt & maskIpInt;
        // 2.计算反掩码
        let widecardInt = !maskIpInt;
        // 3.计算广播地址
        let boardcostInt = networkInt | widecardInt;
        // 4.最后一个可用的fakeip
        let lastIpInt = boardcostInt - 1;

        let lastIp = Ipv4Addr::from(lastIpInt);

        let mut available: Vec<Ipv4Addr> = Vec::new();

        for ipInt in (networkInt + 1)..lastIpInt {
            available.push(Ipv4Addr::from(ipInt));
        }

        let result = Self {
            startIp: start,
            lastIp,
            fakeIpMask: fakeIpMask,
            expireTime: 5 * 60, //5 min
            availableIps: available,
            ip_to_domain: HashMap::new(),
            domain_to_ip: HashMap::new(),
        };

        info!("FakeIpPoolInner initialized successfully with {} available IPs.", lastIpInt - networkInt + 1);
        return result;
    }

    //后台定时任务，清除过期的fakeip
    pub fn cleanFakeIp(&mut self) {
        let mut  expire_ips: Vec<Ipv4Addr> = Vec::new();

        self.domain_to_ip.retain(|domain, fake_ip| {
            if fake_ip.lastTimeUsed.elapsed().as_secs() < self.expireTime { //没有过期
                true
            } else{
                info!("Removing expire fake_ip: {:?}, domain: {:?}", fake_ip.ip, domain);
                expire_ips.push(fake_ip.ip);
                false
            }
        });

        for ip in expire_ips {
            self.ip_to_domain.remove(&ip);
            self.availableIps.push(ip);
        }
    }

    pub fn getFakeIp(&mut self, domain: String) -> Option<Ipv4Addr> {
        if self.domain_to_ip.contains_key(&domain) { //已经存在
            if let Some(ip) = self.domain_to_ip.get_mut(&domain) {
                ip.lastTimeUsed = Instant::now();
                return Some(ip.ip);
            }
            None
        } else {
            if let Some(ip) = self.availableIps.pop() {
                let fake_ip = FakeIp{
                    ip: ip,
                    lastTimeUsed: Instant::now(),
                };
                self.domain_to_ip.insert(domain.clone(), fake_ip);

                self.ip_to_domain.insert(ip, domain.clone());
                info!("Get new fake ip, ip: {:?}, domain: {:?}", ip, &domain);
                return Some(ip);
            } else {
                info!("No available fake IP for domain: {:?}", domain);
                return None;
            }
        }
    }

    pub fn fakeIpToDomain(&self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(&ip).cloned()
    }

}