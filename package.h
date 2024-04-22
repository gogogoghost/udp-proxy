typedef struct EthHeader               /*以太网数据帧头部结构*/
{
    unsigned char      DesMAC[6];      /* destination HW addrress */
    unsigned char      SrcMAC[6];      /* source HW addresss */
    unsigned short     Ethertype;      /* ethernet type */
} ;

typedef struct IPHeader  
{
    UCHAR    iphVerLen;        //版本号和头长度(各占4位)
    UCHAR    ipTOS;            //服务类型
    USHORT    ipLength;        //封包总长度，即整个IP报的长度
    USHORT    ipID;            //封包标识，惟一标识发送的每一个数据报
    USHORT    ipFlags;        //标志
    UCHAR    ipTTL;            //生存时间，就是TTL
    UCHAR    ipProtocol;        //协议，可能是TCP、UDP、ICMP等
    USHORT    ipChecksum;        //校验和
    ULONG    ipSource;        //源IP地址
    ULONG    ipDestination;    //目标IP地址
};

typedef struct UDPHeader
{
    USHORT    sourcePort;        //源端口号
    USHORT    destinationPort;//目的端口号
    USHORT    len;            //封包长度
    USHORT    checksum;        //校验和
};