#!/usr/bin/python
#!/usr/bin/env python

"""Convert NTLMv2 hashes captured with Responder to Hashcat format"""

import logging
import argparse
import sys
import os
import readline

#################################################
#                    Variables                  #
#################################################
__author__ = "Russel Van Tuyl"
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__status__ = "Development"
logging.basicConfig(stream=sys.stdout, format='%(asctime)s\t%(levelname)s\t%(message)s',
                    datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)  # Log to STDOUT
script_root = os.path.dirname(os.path.realpath(__file__))
readline.parse_and_bind('tab: complete')
readline.set_completer_delims('\t')

#################################################
#                   COLORS                      #
#################################################
note = "\033[0;0;33m-\033[0m"
warn = "\033[0;0;31m!\033[0m"
info = "\033[0;0;36mi\033[0m"
question = "\033[0;0;37m?\033[0m"

parser = argparse.ArgumentParser()
parser.add_argument('-F', '--file', type=argparse.FileType('r'), help="File containing password hashes)")
parser.add_argument('-D', '--directory', help="File containing password hashes)")
parser.add_argument('-O', '--output', help="File to save valid )")
args = parser.parse_args()


def parse_file(f):
    """Parse a text file for hashes"""

    hashcat_hashes = []

    hash_file = open(f, "r")
    hash_file_data = hash_file.readlines()
    for line in hash_file_data:
        hash_parts = line.split(":")
        if len(hash_parts) is 6:
            if hash_parts[0].endswith("$"):
                print "["+warn+"]Excluding machine hash: " + hash_parts[0]
            else:
                print "["+info+"]Valid hash for: " + hash_parts[0]
                hashcat_hashes.append(hash_parts[0] + ":" + hash_parts[1] + ":" + hash_parts[2] + ":" + hash_parts[3]
                                      + ":" + hash_parts[4] + ":" + hash_parts[5][:106].rstrip('\n').rstrip('\r'))
        else:
            print "\n["+warn+"]ERROR: Unexpected number of hash parts"
    return hashcat_hashes


def get_path():
    """Prompt the user to enter a directory path"""

    output_path = None
    if args.output:
        if os.path.isdir(os.path.expanduser(args.output)):
            output_path = os.path.expanduser(args.output)

    while output_path is None:
        print "["+question+"]Please enter the directory where you would like the file saved?"
        output_path = raw_input()
        if os.path.isdir(os.path.expanduser(output_path)):
            pass
        else:
            print "["+warn+"]" + str(output_path) + " is not valid, please try again: "
            output_path = None

    return os.path.expanduser(output_path)


def write_file(h):
    """Save hashes to a .txt file"""
    out_dir = get_path()
    hash_file = os.path.join(out_dir, "Hashcat-Hashes.txt")
    f = open(hash_file, 'w')
    for hash_item in h:
        f.write(hash_item + '\n')
    print "["+warn+"]File saved: " + hash_file

if __name__ == '__main__':
    try:
        if args.file:
            print "["+note+"]Reading " + args.file.name + "..."
            hashes = parse_file(args.file.name)
            write_file(hashes)
        elif args.directory:
            print "["+note+"]Reading " + args.directory + "..."
        else:
            print "["+warn+"]No arguments provided!"
            print "["+warn+"]Try: python " + __file__ + " --help"
    except KeyboardInterrupt:
        print "\n["+warn+"]User Interrupt! Quitting...."
    except:
        print "\n["+warn+"]Please report this error to " + __maintainer__ + " by email at: " + __email__
        raise