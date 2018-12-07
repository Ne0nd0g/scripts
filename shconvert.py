#!/usr/bin/env python3

#################################################
#                    Imports                    #
#################################################
import os
import argparse
import base64

#################################################
#                    Variables                  #
#################################################
__author__ = "Russel Van Tuyl"
__version__ = "1.0"
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
VERBOSE = False
DEBUG = False

#################################################
#                   COLORS                      #
#################################################
note = "\033[0;0;33m[-]\033[0m"
warn = "\033[0;0;31m[!]\033[0m"
info = "\033[0;0;36m[i]\033[0m"
question = "\033[0;0;37m[?]\033[0m"
debug = "\033[0;0;31m[DEBUG]\033[0m"


def convert_shellcode():
	"""Convert a RAW file into various output formats"""

	sc_data = args.readfile.read()
	binary_code = ''

	# Print in standard shellcode format \x41\x42\x43
	for byte in sc_data:
	    binary_code += "\\x" + hex(byte)[2:].zfill(2)

	if args.standard:
		print(info + "Standard shellcode format:\r\n%s" % (binary_code))
		if args.writefile:
			write_output(binary_code, "standard.shellcode.txt")

	cs_shellcode = "0" + ",0".join(binary_code.split("\\")[1:])
	if args.csharp:
		print(info + "CSharp shellcode format:\r\n%s" % (cs_shellcode))
		if args.writefile:
			write_output(cs_shellcode, 'csharp.shellcode.txt')

	# Base 64 encode the C# code for use with certain payloads
	if args.base64:
		encoded_cs = base64.b64encode(cs_shellcode.encode())
		print(info + "CSharp Base64 encoded shellcode format:\r\n%s" % (encoded_cs.decode('ascii')))
		if args.writefile:
			write_output(encoded_cs.decode('ascii'), "csharp.base64.shellcode.txt")


def write_output(shcode, filename):

	"""Write out the files to disk (edit this path as needed)"""
	with open(filename, 'w') as format_out:
		format_out.write(shcode)


if __name__ == '__main__':
    """Main function for converting RAW file"""
	# Modified from https://github.com/ChrisTruncer/PenTestScripts/blob/master/shellcodemodifier.py

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--readfile', type=argparse.FileType('rb'), required=True, help="Path to RAW file for conversion")
    parser.add_argument('-s', '--standard', action='store_true', default=False, help='Convert RAW file to standard shellcode format (i.e. \\x42\\x90)')
    parser.add_argument('-c','--csharp', action='store_true', default=False, help="Convert RAW file to C# style shellcode format (i.e. 0x42,0x90")
    parser.add_argument('-b','--base64', action='store_true', default=False, help="Convert RAW file to Base64 encoded version of the C# style shellcode format")
    parser.add_argument('-w','--writefile', action='store_true', default=False, help="Save output to a file in the current directory")
    parser.add_argument('--verbose', action='store_true', default=False, help="Enable verbose output")
    parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output")
    args = parser.parse_args()

    DEBUG = args.debug
    VERBOSE = args.verbose

    try:
    	convert_shellcode()

    except KeyboardInterrupt:
        print("\n" + warn + "User Interrupt! Quitting....")
    except SystemExit:
        pass
    except:
        print("\n" + warn + "Please report this error to " + __maintainer__ + " by email at: " + __email__)
        raise
