

from xml.etree import ElementTree
import argparse
import logging
import sys
import os
import readline
import hashlib

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

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-X', '--xml', type=argparse.FileType('r'), help="Netsparker XML file")
parser.add_argument('-D', '--directory', help="Directory containing Netsparker XML files")
parser.add_argument('-v', '--verbose', action='store_true', default=False, help="Print verbose information")
parser.add_argument('-m', '--md5', action='store_true', default=False, help="Print MD5 hash of vulnerability")
args = parser.parse_args()

def read_xml(xml_file):
    """Parse file and create xml root element"""

    print "[" + info + "]Parsing: ", xml_file
    xml_tree = ElementTree.parse(xml_file)
    xml = xml_tree.getroot()

    if xml.tag == 'netsparker':
        return xml
    else:
        return None

def read_directory():

    files = []
    directory_files = None
    if os.path.isdir(os.path.expanduser(args.directory)):
        directory_files = os.listdir(args.directory)

    if directory_files is not None:
        for f in directory_files:
            if f.endswith('.xml'):
                files.append(os.path.join(args.directory, f))

    return files

def parse(xml):
    """Main Netsparker Parse Function"""

    netsparker = {}  # Dictionary to hold all parsed data

    #Verify Netsparker XML
    if xml.tag != 'netsparker':
        print "[" + warn + "The specefied file does not appear to be a Netsparker XML"
        print "[" + warn + "The root element is: " + xml.tag
        sys.exit()
    target = xml.findtext('./target/url')
    print "[" + note + "]Target: ", target
    if target is not None:
        netsparker[target] = {'target_url': target, 'vulnerabilities': {}}

    for vulnerability in xml.findall('./vulnerability'):
        #Gather Important Data
        url = vulnerability.findtext('./url')
        type = vulnerability.findtext('./type')
        severity = vulnerability.findtext('./severity')
        certainty = vulnerability.findtext('./certainty')
        m = hashlib.md5()
        m.update(type)
        md5 = m.hexdigest()
        if args.md5:
            print "\t[" + info + "]" + type + "\t" + md5.upper()
        else:
            print "\t[" + info + "]" + type

        #Add Data to Dictionary
        if type in netsparker[target]['vulnerabilities'].keys():
            netsparker[target]['vulnerabilities'][type].update({url:{'url': url, 'severity': severity,
                                                                     'certainty': certainty}})
        else:
            netsparker[target]['vulnerabilities'][type] = {url:{'url': url, 'severity': severity,
                                                                'certainty': certainty}}

        if args.verbose:
            print "\t\t[" + info + "]URL: ", url
            print "\t\t[" + info + "]Severity: ", severity
            print "\t\t[" + info + "]MD5: ",md5.upper()
            print "\t\t[" + info + "]Certainty: ", certainty
    return netsparker


if __name__ == '__main__':
    try:
        if args.xml:
            netsparker_xml = read_xml(args.xml)
            if netsparker_xml is not None:
                netsparker_object = parse(netsparker_xml)
        elif args.directory:
            xml_files = read_directory()
            netsparker_object = {}
            if len(xml_files) > 0:
                for f in xml_files:
                    netsparker_xml = read_xml(f)
                    netsparker_object.update(parse(netsparker_xml))
            # print netsparker_object
        else:
            print "["+warn+"]No arguments provided!"
            print "["+warn+"]Try: python " + __file__ + " --help"
    except KeyboardInterrupt:
        print "\nUser Interrupt! Quitting...."
    except:
        print "\nPlease report this error to " + __maintainer__ + " by email at: " + __email__
        raise

# Data Structure

# <target> dict
#   <target_url> value
#   <vulnerabilities> dict
#       <md5 hash> dict
#       <target_url> dict
#           <target_url> value
#           <target_severity> value
#           <tartet_certainty> value
#           <target_raw_request> value
#           <target_raw_response> value
