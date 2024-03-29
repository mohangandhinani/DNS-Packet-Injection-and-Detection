import argparse
from datetime import datetime

from scapy.all import *

detect_dict = {}


def executor():
    parsed_args = arg_parser()
    # print_args(parsed_args)
    if parsed_args.interface and parsed_args.trace_file_path:
        print "Please use interface or trace option"
        return
    if parsed_args.bpf_filter:
        parsed_args.bpf_filter = " ".join(parsed_args.bpf_filter)

    if parsed_args.trace_file_path:
        sniff(filter=parsed_args.bpf_filter, prn=spoofing_detect, store=0, offline=parsed_args.trace_file_path)
    else:
        filter = "udp port 53 and {bpf}".format(bpf=parsed_args.bpf_filter) if parsed_args.bpf_filter else 'udp port 53'
        if parsed_args.interface is not None:
            sniff(filter=filter, iface=parsed_args.interface, store=0, prn=spoofing_detect)
        else:
            sniff(filter=filter, store=0, prn=spoofing_detect)


def arg_parser():
    # Required Options
    parser = argparse.ArgumentParser(prog='dns_packet_injector.py',
                                     description="Please specify the interface to capture ,tracefile path ",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--interface', help="interface to capture")
    parser.add_argument('-r', '--trace_file_path', help="please provide the trace file path")
    parser.add_argument('bpf_filter', nargs='*', help='bpf filter name')
    parsed_args = parser.parse_args()
    return parsed_args


def print_args(parsed_args):
    if parsed_args.interface is None:
        print "No interface given capturing on all interfaces"
    else:
        print "capturing on {interface}".format(interface=parsed_args.interface)

    if parsed_args.trace_file_path is None:
        print "No trace file given"
    else:
        print "trace file is {trace_file}".format(trace_file=parsed_args.trace_file_path)

    if parsed_args.bpf_filter is None:
        print "No bpf filter given"
    else:
        print "BPF filter is {bpf_filter}".format(bpf_filter=parsed_args.bpf_filter)


def spoofing_detect(pack):
    prev_pack = previous_packet(pack)
    if prev_pack and prev_pack[IP].dst == pack[IP].dst and \
                    prev_pack[IP].sport == pack[IP].sport and \
                    prev_pack[IP].dport == pack[IP].dport and \
                    prev_pack[DNS].qd.qname == pack[DNS].qd.qname and \
                    prev_pack[IP].payload != pack[IP].payload:

        a1_l = []
        a2_l = []
        for i in xrange(pack[DNS].ancount):
            if pack[DNS].an[i].type == 1:
                a1_l.append(pack[DNS].an[i].rdata)
        for j in xrange(prev_pack[DNS].ancount):
            if prev_pack[DNS].an[j].type == 1:
                a2_l.append(prev_pack[DNS].an[j].rdata)
        spoof_flag = 0
        if not (set(a1_l) & set(a2_l)):
            spoof_flag = 1
        if not (pack[IP].ttl == prev_pack[IP].ttl):
            spoof_flag = 1
        if not (pack[Ether].src == prev_pack[Ether].src):
            spoof_flag = 1
        if spoof_flag:
            print "{time} DNS poisoning attempt".format(
                time=datetime.fromtimestamp(pack.time).strftime('%Y-%m-%d %H:%M:%S'))
            print "TXID {t_id} Request {request_name}".format(t_id=pack[DNS].id,
                                                              request_name=pack[DNS].qd.qname.strip())
            print "Answer1 {prev_data}".format(prev_data=" ".join(a1_l))
            print "Answer2 {present_data}\n\n".format(present_data=" ".join(a2_l))


def previous_packet(pack):
    if len(detect_dict) == 1000:
        detect_dict.clear()
    if pack.haslayer(DNSRR) and pack.haslayer(DNS):
        key = pack[IP].dst + '_' + str(pack[DNS].id)
        prev_pack = detect_dict.get(key, None)
        if prev_pack is None:
            detect_dict[key] = pack
        else:
            return prev_pack
    else:
        return False


if __name__ == "__main__":
    executor()



