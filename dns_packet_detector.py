import argparse

detect_dict = {}


def detector(pack):
    prev_pack = is_valid_packet(pack)
    if prev_pack[IP].dst == pack[IP].dst and \
       prev_pack[IP].sport == pack[IP].sport and \
       prev_pack[IP].dport == pack[IP].dport and \
       prev_pack[DNSRR].rdata != pack[DNSRR].rdata and \
       prev_pack[DNS].qd.qname == pack[DNS].qd.qname and \
       prev_pack[IP].payload != pack[IP].payload:
    # //FIXME : add ip a checking
    # //FIXME : source  ip same?
    print "DNS poisoning attempt"
    print "TXID {t_id} Request {request_name}".format(t_id=op[DNS].id, request_name=op[DNS].qd.qname.rstrip('.'))
    print "Answer1 {prev_data}".format(prev_data=op[DNSRR].rdata)
    print "Answer2 {present_data}".format(present_data=pkt[DNSRR].rdata)


def is_valid_packet(pack):
    if DNS in pack and DNSRR in pack:
        prev_pack = detect_dict.get(pack[DNS].id, None)
        if prev_pack is None:
            detect_dict[pack[DNS].id] = pack
        else:
            return prev_pack
    else:
        return False


def arg_parser():
    # Required Options
    parser = argparse.ArgumentParser(prog='dns_packet_injector.py',
                                     description="Please specify the interface to capture ,tracefile path ",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--interface', help="interface to capture")
    parser.add_argument('-r', '--trace_file_path', help="please provide the trace file path")
    parsed_args = parser.parse_args()
    return parsed_args

def executor():
    # elif flagi == 0 and flagt == 1:
    # print "Sniffing from the tracefile"
    # sniff(filter=expression, offline=tracefile, store=0, prn=dns_detect)
    # elif flagi == 1:
    # print "Sniffing on interface"
    # sniff(filter=expression, iface=interface, store=0, prn=dns_detect)
    # else:
    # print "sniffing on all interfaces"
    # sniff(filter=expression, store=0, prn=dns_detect)
    #

if __name__ == "__main__":
    print arg_parser()
