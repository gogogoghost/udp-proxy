use std::borrow::Borrow;
use std::ffi::CStr;
use std::mem::size_of;
use std::{ffi::CString, mem::MaybeUninit};
use std::fs::File;

use encoding_rs::GBK;
use udp_proxy::pcap;
use std::collections::HashMap;
use std::io::BufReader;
use std::io::BufRead;
use std::net::Ipv4Addr;

static mut FORWARD_INTERFACE:*mut pcap::pcap_t=std::ptr::null_mut();
static mut LISTEN_DEST_IP:Vec<u32>=Vec::new();
static mut FORWARD_DEST_IP:Vec<u32>=Vec::new();
static mut MY_IP:u32=0;

fn decode_ip(src:&u32)->String{
    let buf=src.to_be_bytes();
    format!("{}.{}.{}.{}",buf[0],buf[1],buf[2],buf[3])
}

fn encode_ip(src:&str)->u32{
    let ip:u32=src.parse::<Ipv4Addr>().expect(format!("invalid ip: {}",src).borrow()).into();
    ip
}

fn gen_ip_checksum(ptr:* const pcap::IPHeader)->u16{
    let mut sum: u32 = 0;

    // 将头部结构体转换为字节数组
    let header_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, std::mem::size_of::<pcap::IPHeader>())
    };

    // 遍历每两个字节，计算校验和
    for i in (0..header_bytes.len()).step_by(2) {
        if i != 10 { // Skip checksum field itself
            sum += u16::from_be(u16::from(header_bytes[i]) << 8 | u16::from(header_bytes[i + 1])) as u32;
        }
    }

    // 将进位加到低 16 位上
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn gen_udp_checksum(ptr:* const pcap::UDPHeader,src_ip:&u32,dest_ip:&u32,payload:&[u8])->u16{
    let mut sum: u32 = 0;
    // 伪首部
    let pseudo_header = [
        (src_ip >> 16) as u16,
        (src_ip & 0xFFFF) as u16,
        (dest_ip >> 16) as u16,
        (dest_ip & 0xFFFF) as u16,
        0x0011, // Protocol: UDP
        unsafe{(*ptr).len.to_be()},
    ];
    // 计算伪首部的校验和
    for &word in &pseudo_header {
        sum += u32::from(word);
    }

    // 计算 UDP 头部的校验和
    let udp_header_bytes: &[u16] = unsafe {
        std::slice::from_raw_parts(ptr as *const u16, std::mem::size_of::<pcap::UDPHeader>()/2)
    };
    for i in 0..udp_header_bytes.len(){
        sum+=u32::from(u16::from_be(udp_header_bytes[i]));
    }
    // 计算 UDP 数据部分的校验和
    for i in (0..payload.len()).step_by(2) {
        let word = if i + 1 < payload.len() {
            u16::from(payload[i]) << 8 | u16::from(payload[i + 1])
        } else {
            u16::from(payload[i]) << 8
        };
        sum += u32::from(word);
    }

    // 将进位加到低 16 位上
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

unsafe extern fn handle_pkg(_:*mut u8,header:*const pcap::pcap_pkthdr,data:*const u8){
    let eth_size=size_of::<pcap::EthHeader>();
    let ip_size=size_of::<pcap::IPHeader>();
    let udp_size=size_of::<pcap::UDPHeader>();
    //跳过eth头
    let data_ptr=data.add(eth_size);
    //解析ip头
    let iphdr_ptr = data_ptr as *mut pcap::IPHeader;
    let iphdr=*iphdr_ptr;
    let origin_dest_ip=iphdr.ipDestination.to_be();
    if LISTEN_DEST_IP.contains(&origin_dest_ip){
        println!("detected {} -> {}",decode_ip(&iphdr.ipSource.to_be()),decode_ip(&iphdr.ipDestination.to_be()));
        //转发数据包
        let total=(*header).caplen as usize;
        let size=total - eth_size;
        let mut buf = Vec::<u8>::with_capacity(size);
        let buf_ptr=buf.as_mut_ptr();
        buf.set_len(size);
        std::ptr::copy(data_ptr, buf_ptr, size);
        for dest_ip in &FORWARD_DEST_IP{
            println!("forward -> {}",decode_ip(dest_ip));
            //修改
            let iphdr_ptr=buf_ptr as *mut pcap::IPHeader;
            // let mut iphdr=*iphdr_ptr;
            let src_ip=encode_ip("100.64.0.1");
            (*iphdr_ptr).ipSource=src_ip.to_be();
            (*iphdr_ptr).ipDestination=dest_ip.to_be();
            //修改checksum
            (*iphdr_ptr).ipChecksum=0;
            (*iphdr_ptr).ipChecksum=gen_ip_checksum(iphdr_ptr);
            //修改udp头部
            let udp_ptr=buf_ptr.add(ip_size) as * mut pcap::UDPHeader;
            let payload=&buf[ip_size+udp_size..];
            (*udp_ptr).checksum=0;
            (*udp_ptr).checksum=gen_udp_checksum(
                udp_ptr, 
                &src_ip, 
                dest_ip,
                payload
            ).to_be();
            //发送
            let res=pcap::pcap_sendpacket(FORWARD_INTERFACE, buf_ptr, size as i32);
            if res!=0{
                println!("failed to forward");
            }
        }
    }
}

fn err_panic(msg:&str,err_buf:&Vec<i8>){
    let len = err_buf.iter().position(|&x| x == 0).unwrap_or(err_buf.len());
    let buf=&err_buf[..=len];
    let u8_buf: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };
    let (decoded_string, _, _) = GBK.decode(u8_buf);
    panic!("{}{}",msg,decoded_string);
}
fn read_config()->HashMap<String,String>{
    // 打开文件
    let file = File::open("config.prop").expect("Failed to open config file");
    // 创建一个 HashMap 用于存储配置数据
    let mut config_data = HashMap::new();

    // 逐行读取文件内容，并解析键值对
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() == 2 {
            let key = parts[0].trim();
            let value = parts[1].trim();
            config_data.insert(key.to_string(), value.to_string());
        }
    }
    config_data
}

unsafe fn decode_str<'a>(ptr:*const i8)->std::borrow::Cow<'a, str>{
    let gbk_slice: &'a[u8] = CStr::from_ptr(ptr).to_bytes();
    let (str, _, _) = GBK.decode(gbk_slice);
    return str
}

fn main() {
    let props=read_config();
    //读取监听ip
    for listen_ip in props["LISTEN_DEST_IP"].split(","){
        unsafe{
            LISTEN_DEST_IP.push(encode_ip(listen_ip));
        }
    }
    //读取目标ip
    for forward_ip in props["FORWARD_DEST_IP"].split(","){
        unsafe{
            FORWARD_DEST_IP.push(encode_ip(forward_ip));
        }
    }
    let capture_interface=&props["CAPTURE_INTERFACE"];
    let forward_interface=&props["FORWARD_INTERFACE"];
    let mut err_buf:Vec<i8>=vec![0;pcap::PCAP_ERRBUF_SIZE as usize];
    //初始化
    unsafe{
        let res=pcap::pcap_lib_version();
        println!("npcap version: {}",decode_str(res));
    };
    //遍历一下
    let mut all_dev_ptr:MaybeUninit<* mut pcap::pcap_if_t>=MaybeUninit::uninit();
    let mut dev_ptr:MaybeUninit<* mut pcap::pcap_if_t>=MaybeUninit::uninit();
    unsafe{
        let res=pcap::pcap_findalldevs(all_dev_ptr.as_mut_ptr(), err_buf.as_mut_ptr());
        if res !=0 {
            err_panic("find fail: ",&err_buf);
        }
        dev_ptr=all_dev_ptr;
        while !(*dev_ptr.as_mut_ptr()).is_null(){
            let dev=**dev_ptr.as_ptr();
            let name=decode_str(dev.name);
            println!("Name:{}",decode_str(dev.name));
            println!("Desc:{}",decode_str(dev.description));
            // if forward_interface.eq(&name){
            //     //网卡是forward网卡
            //     let addr=*(*dev.addresses).addr;
            //     if addr.sa_family==2{
            //         //地址是ipv4
            //         let mut arr:[u8;4]=[0,0,0,0];
            //         for i in 0..4 {
            //             arr[i]=addr.sa_data[i+2] as u8;
            //         }
            //         MY_IP=Ipv4Addr::from(arr).into();
            //     }
            // }
            *dev_ptr.as_mut_ptr()=dev.next;
        }
        pcap::pcap_freealldevs(*all_dev_ptr.as_mut_ptr());
    };
    //初始化
    let handle=unsafe{
        let inter_name = CString::new(capture_interface.to_owned()).unwrap();
        let handle=pcap::pcap_open_live(
            inter_name.as_ptr(),
             65535, 
             1, 
             1000, 
             err_buf.as_mut_ptr()
        );
        if handle.is_null(){
            err_panic("cannot find capture interface: ",&err_buf)
        }
        handle
    };
    unsafe{
        let inter_name = CString::new(forward_interface.to_owned()).unwrap();
        let handle=pcap::pcap_open_live(
            inter_name.as_ptr(),
             65535, 
             1, 
             1000, 
             err_buf.as_mut_ptr()
        );
        if handle.is_null(){
            err_panic("cannot find forward interface: ",&err_buf)
        }
        FORWARD_INTERFACE=handle
    };
    
    //过滤器
    let mut fp:MaybeUninit<pcap::bpf_program>=MaybeUninit::uninit();
    unsafe{
        let filter=CString::new("udp").unwrap();
        pcap::pcap_compile(
            handle, 
            fp.as_mut_ptr(),
             filter.as_ptr(),
            1,
            pcap::PCAP_NETMASK_UNKNOWN
            );
        pcap::pcap_setfilter(handle, fp.as_mut_ptr());
    }
    //开始捕获
    println!("Start forwarding...");
    unsafe{
        pcap::pcap_loop(handle,0,Some(handle_pkg),std::ptr::null_mut());
    }
    
}
