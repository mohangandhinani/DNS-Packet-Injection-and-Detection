import argparse


def arg_parser():
    # Required Options
    parser = argparse.ArgumentParser(prog='dns_packet_injector.py',
                                     description="Please specify the interface to capture ,tracefile path ",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--interface', help="interface to capture")
    parser.add_argument('-r', '--trace_file_path', help="please provide the trace file path")
    parsed_args = parser.parse_args()
    return parsed_args


if __name__ == "__main__":
    print arg_parser()
