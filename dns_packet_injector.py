import argparse

from scapy.all import sniff


def arg_parser():
    # Required Options
    parser = argparse.ArgumentParser(prog='dns_packet_injector.py',
                                     description="Please specify the interface to capture ,host_names ",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter, add_help=False)
    parser.add_argument('-i', '--interface', help="interface to capture")
    parser.add_argument('-h', '--host_names', help="hostname to capture")
    parser.add_argument('--bpf_filter', nargs='*', help='bpf filter name')
    parsed_args = parser.parse_args()
    return parsed_args


def packet_spoofing(pack):
    pack = 1
    send(pack)
    print "New packet is ",pack.summary()


def executor(parsed_args):
    if parsed_args.interface is not None:
        sniff(filter='udp port 53', iface=parsed_args.interface, store=0, prn=packet_spoofing)
    else:
        sniff(filter='udp port 53', store=0, prn=packet_spoofing)


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


if __name__ == "__main__":
    parsed_args = arg_parser()
    print_args(parsed_args)
    executor(parsed_args)
