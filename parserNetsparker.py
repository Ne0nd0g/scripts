

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
VERBOSE = False
CVE = False
MD5 = False
VULNS = False


def read_xml(xml_file):
    """Parse file and create xml root element"""

    if VERBOSE:
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

    # Verify Netsparker XML
    if xml.tag != 'netsparker':
        print "[" + warn + "The specefied file does not appear to be a Netsparker XML"
        print "[" + warn + "The root element is: " + xml.tag
        sys.exit()
    target = xml.findtext('./target/url')
    if VERBOSE or CVE or MD5 or VULNS:
        print "[" + note + "]Target: ", target
    if target is not None:
        netsparker[target] = {'target_url': target, 'vulnerabilities': {}}

    for vulnerability in xml.findall('./vulnerability'):
        # Gather Important Data
        url = vulnerability.findtext('./url')
        type = vulnerability.findtext('./type')
        severity = vulnerability.findtext('./severity')
        certainty = vulnerability.findtext('./certainty')
        m = hashlib.md5()
        m.update(type)
        md5 = m.hexdigest().upper()
        if MD5:
            print "\t[" + warn + "][%s]\t%s" % (md5, type)
        elif VULNS or CVE or VERBOSE:
            print "\t[" + warn + "]" + type

        # Version Information
        # TODO add to Netsparker Dictionary
        if vulnerability.findall('./extrainformation') is not None:
            for z in vulnerability.findall('./extrainformation/info'):
                if VERBOSE:
                    print "\t\t[" + info + "]%s: %s" % (z.get('name'), z.text)

        # Vulnerabilities listed inside vulnerabilities i.e out of date openssl
        # TODO add to Netsparker Dictionary
        if vulnerability.findall('./knownvulnerabilities') is not None:
            for v in vulnerability.findall('./knownvulnerabilities/knownvulnerability'):
                m2 = hashlib.md5()
                m2.update(v.findtext('./title'))
                md52 = m2.hexdigest().upper()
                if CVE:
                    print "\t\t[" + warn + "]%s\t[%s]\t%s" % (v.findtext('./references'),
                                                              md52,
                                                              v.findtext('./title'))
        # TODO Add Data to Dictionary
        if type in netsparker[target]['vulnerabilities'].keys():
            netsparker[target]['vulnerabilities'][type].update({url:{'url': url, 'severity': severity,
                                                                     'certainty': certainty}})
        else:
            netsparker[target]['vulnerabilities'][type] = {url:{'url': url, 'severity': severity,
                                                                'certainty': certainty}}

        if VERBOSE:
            print "\t\t[" + info + "]URL: ", url
            print "\t\t[" + info + "]Severity: ", severity
            print "\t\t[" + info + "]MD5: ",md5.upper()
            print "\t\t[" + info + "]Certainty: ", certainty
    return netsparker


if __name__ == '__main__':
    try:

        # Parse command line arguments
        parser = argparse.ArgumentParser()
        file_group = parser.add_mutually_exclusive_group(required=True)
        file_group.add_argument('-X', '--xml', type=argparse.FileType('r'), help="Netsparker XML file")
        file_group.add_argument('-D', '--directory', help="Parse all XML files in directory")
        parser.add_argument('-c', '--cve', action='store_true', default=False, help="Print CVE information")
        parser.add_argument('-m', '--md5', action='store_true', default=False, help="Print MD5 hash of vulnerability")
        parser.add_argument('-V', '--vulns', action='store_true', default=False, help="List found vulnerabilities")
        parser.add_argument('-v', '--verbose', action='store_true', default=False, help="Print verbose information")
        args = parser.parse_args()

        if args.verbose:
            VERBOSE = True
        if args.md5:
            MD5 = True
        if args.cve:
            CVE = True
        if args.vulns:
            VULNS = True
        if args.xml:
            netsparker_xml = read_xml(args.xml)
            if netsparker_xml is not None:
                netsparker_object = parse(netsparker_xml)
        if args.directory:
            xml_files = read_directory()
            netsparker_object = {}
            if len(xml_files) > 0:
                for f in xml_files:
                    netsparker_xml = read_xml(f)
                    netsparker_object.update(parse(netsparker_xml))
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
#           <target_CVE> list of
