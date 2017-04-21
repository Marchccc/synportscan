#include "home.h"
#include "ui_home.h"

#include <iomanip>
#include <vector>
#include <set>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/ip_address.h>
#include <tins/ethernetII.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <tins/utils.h>
#include <tins/packet_sender.h>
#include <iostream>

#include <QDebug>

#include <sstream>
using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::pair;
using std::setw;
using std::set;
using std::runtime_error;
using std::to_string;
using namespace Tins;

//f
//void Home::ChangUis(QString);
void ChangUis(string a);
typedef pair<Sniffer*, string> sniffer_data;
// 定义用来修改内容的方法
//void toText(int,int);

class Scanner {
public:
    Scanner(const NetworkInterface& interface,
            const IPv4Address& address,
            const int ports);

    void run();
private:
    void send_syns(const NetworkInterface& iface, IPv4Address dest_ip);
    bool callback(PDU& pdu);
    static void* thread_proc(void* param);
    void launch_sniffer();

    NetworkInterface iface;
    IPv4Address host_to_scan;
    set<uint16_t> ports_to_scan;
    Sniffer sniffer;

//    Home *m_pHome;
//    ui;
};

Scanner::Scanner(const NetworkInterface& interface,
                 const IPv4Address& address,
                 const int ports)
: iface(interface), host_to_scan(address), sniffer(interface.name()) {
    sniffer.set_filter(
        "tcp and ip src " + address.to_string() + " and tcp[tcpflags] & (tcp-rst|tcp-syn) != 0"
    );
    // for (size_t i = 0; i < ports.size(); ++i) {
    //     cout << ports[i].c_str() << endl;
    //     ports_to_scan.insert(atoi(ports[i].c_str()));
    // }
    // int port = 80;
    ports_to_scan.insert(ports);

//    m_pHome = new Home();
//    uis = ui;
}

void* Scanner::thread_proc(void* param) {
    Scanner* data = (Scanner*)param;
    data->launch_sniffer();
    return 0;
}

void Scanner::launch_sniffer() {
    sniffer.sniff_loop(make_sniffer_handler(this, &Scanner::callback));
}

/* 我们的扫描处理程序。这将得到SYNs rst和通知我们扫描端口的状态。
 */
bool Scanner::callback(PDU& pdu) {
    // Find the layers we want.
    // 找到我们想要的层。
    const IP& ip = pdu.rfind_pdu<IP>();
    const TCP& tcp = pdu.rfind_pdu<TCP>();
    // Check if the host that we're scanning sent this packet and
    // 检查主机是否我们扫描发送这个数据包
    // the source port is one of those that we scanned.
    // 源端口是那些我们扫描
    if(ip.src_addr() == host_to_scan && ports_to_scan.count(tcp.sport()) == 1) {
        // 这不是一个TCP/PDU。这个端口关闭
        if(tcp.get_flag(TCP::RST)) {
            // 这表明我们应该停止嗅探
            if(tcp.get_flag(TCP::SYN))
                return false;
//            cout << "Port: " << setw(5) << tcp.sport() << " closed\n";
            string a = ip.src_addr().to_string()+"     ";
            std::stringstream sstr;
            string port_str;
            sstr<<tcp.sport();
            sstr>>port_str;
            a+=port_str;
            a+="    close";
            ChangUis(a);
        }
        // 端口打开
        else if(tcp.flags() == (TCP::SYN | TCP::ACK)) {
//            cout << "Port: " << ip.src_addr() << setw(5) << tcp.sport() << " open\n";
            string a = ip.src_addr().to_string()+"     ";
            std::stringstream sstr;
            string port_str;
            sstr<<tcp.sport();
            sstr>>port_str;
            a+=port_str;
            a+="    open";
            ChangUis(a);
        }
    }
    return true;
}

void Scanner::run() {
    pthread_t thread;
    // Launch our sniff thread.
    // 启动嗅探线程
    pthread_create(&thread, 0, &Scanner::thread_proc, this);
    // Start sending SYNs to port.
    // 开始发送SYNs端口。
    send_syns(iface, host_to_scan);

    // Wait for our sniffer.
    // 等待我们的嗅探器。
    void* dummy;
    pthread_join(thread, &dummy);
}

// Send syns to the given ip address, using the destination ports provided.
// 发送syns给定ip地址,使用提供的目的地港口
void Scanner::send_syns(const NetworkInterface& iface, IPv4Address dest_ip) {
    // Retrieve the addresses.
    // 检索地址。
    NetworkInterface::Info info = iface.addresses();
    PacketSender sender;
    // Allocate the IP PDU
    // 分配IP PDU
    IP ip = IP(dest_ip, info.ip_addr) / TCP();
    // Get the reference to the TCP PDU
    // 对TCP PDU的引用
    TCP& tcp = ip.rfind_pdu<TCP>();
    // Set the SYN flag on.
    tcp.set_flag(TCP::SYN, 1);
    // Just some random port.
    // 只是一些随机端口
    tcp.sport(1337);
    cout << "Sending SYNs..." << endl;
    for (set<uint16_t>::const_iterator it = ports_to_scan.begin(); it != ports_to_scan.end(); ++it) {
        // Set the new port and send the packet!
        tcp.dport(*it);
        sender.send(ip);
    }
    // Wait 1 second.
    sleep(1);
    /* Special packet to indicate that we're done. This will be sniffed
     * by our function, which will in turn return false.
     */
    tcp.set_flag(TCP::RST, 1);
    tcp.sport(*ports_to_scan.begin());
    // Pretend we're the scanned host...
    ip.src_addr(dest_ip);
    // We use an ethernet pdu, otherwise the kernel will drop it.
    EthernetII eth = EthernetII(info.hw_addr, info.hw_addr) / ip;
    sender.send(eth, iface);
}

void scan(string ip_str,int port) {
    IPv4Address ip(ip_str);
    // Resolve the interface which will be our gateway
    // 解决将是我们网关的接口
    NetworkInterface iface(ip);
    Scanner scanner(iface,ip,port);
    scanner.run();
}

Home *Home::m_pHome = NULL;//静态对象初始化
Home::Home(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Home)
{
    ui->setupUi(this);

    ui->lineEdit->setText("180.76.138.175");
    ui->lineEdit_2->setText("80");
    ui->resTxt->setText("");
    //给静态对象赋值
    m_pHome = this;

}

Home::~Home()
{
    delete ui;
}

void ChangUis(string a)
{
    Home *HuoQiLinGG = Home::m_pHome;
    QString addTxt;
    addTxt = QString::fromStdString(a);
    HuoQiLinGG->ui->resTxt->append(addTxt);

}
void Home::on_pushButton_clicked()
{

    QString st = ui->lineEdit->text();
    string ip_str = st.toStdString();
    QString qstring_port = ui->lineEdit_2->text();
    int port = qstring_port.toInt();
    scan(ip_str,port);
}
