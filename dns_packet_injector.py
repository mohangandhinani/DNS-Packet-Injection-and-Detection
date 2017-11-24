import argparse


def arg_parser():
    # Required Options
    parser = argparse.ArgumentParser(prog='execute_mt.py', formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-i', '--interface', help="interface to capture")
    parser.add_argument('-h', '--hostnames',  help="hostname to capture",
                               )
    output_dict = parser.parse_args()
    return output_dict

if __name__=="__main__":
    print arg_parser()
