__author__ = 'Russel Van Tuyl'
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"

from xml.etree import ElementTree
import argparse
import hashlib
import os

#################################################
#                   COLORS                      #
#################################################
note = "[\033[0;0;33m-\033[0m]"
warn = "[\033[0;0;31m!\033[0m]"
info = "[\033[0;0;36mi\033[0m]"
question = "[\033[0;0;37m?\033[0m]"

# Parse command line arguments
parser = argparse.ArgumentParser()
file_group = parser.add_mutually_exclusive_group(required=True)
file_group.add_argument('-X', '--xml', type=argparse.FileType('r'), help="Acunetix XML file")
file_group.add_argument('-D', '--directory', help="Parse all XML files in directory")

# parser.add_argument('-X', '--xml', type=argparse.FileType('r'), required=False, help="Acunetix XML file")
# parser.add_argument('-D', '--directory', action='store_true', default=False, help="Parse all XML files in directory")
parser.add_argument('-U', '--URL', action='store_true', default=False, help="List found URLs")
parser.add_argument('-d', '--directories', action='store_true', default=False, help="List found directories")
parser.add_argument('-F', '--files', action='store_true', default=False, help="List found files")
parser.add_argument('-V', '--vulns', action='store_true', default=True, help="List found vulnerabilities. Default=True")
parser.add_argument('-m', '--md5', action='store_true', default=False, help="Print MD5 hash of vulnerability")
parser.add_argument('-i', '--insensitive', action='store_true', default=False, help="Case Insensitive Output")
parser.add_argument('-v', '--verbose', action='store_true', default=False, help="Verbose Output")
args = parser.parse_args()

def parse(xml_file):
    """Parse XML file and return ElementTree object"""
    if args.verbose:
        print str(xml_file)
    xml_tree = ElementTree.parse(xml_file)

    return xml_tree


def get_urls(acunetix_xml):
    """Get a list of URLs for all discovered files and directories"""
    urls = []  # A list to hold all discovered paths

    for site_files in acunetix_xml.find('.//SiteFiles'):
        for site_file in site_files:
            url = site_files.find('./FullURL').text.strip('%20')
            if args.insensitive:
                if url.lower() not in urls:
                    urls.append(url.lower())
            else:
                if url not in urls:
                    urls.append(url)

    return sorted(set(urls), key=str.lower)


def get_paths(acunetix_xml):
    """Parse a list of found directories and file names"""

    urls = []  # A list to hold all discovered paths

    for site_files in acunetix_xml.find('.//SiteFiles'):
        for site_file in site_files:
            url = site_files.find('./URL').text.split('/')
            for u in url:
                if args.insensitive:
                    if u.lower() not in urls:
                        urls.append(u.lower())
                else:
                    if u not in urls:
                        urls.append(u)
                #print "URL: ", type(i)
            #if "." not in url.text:
                #urls.append(str(url.text).strip('%20').lstrip('/').rstrip('/'))

    return sorted(set(urls), key=str.lower)


def get_files(acunetix_xml):
    """Get a sorted list of all discovered files"""
    files = []  # A list to hold all discovered files
    for site_files in acunetix_xml.find('.//SiteFiles'):
        for site_file in site_files:
            f = site_files.find('./URL')
            if "." in f.text:
                files.append(str(f.text).strip('%20'))

    return sorted(set(files), key=str.lower)


def get_report_items(acunetix_xml):
    """Get Acunetix report findings"""

    report_items = {}

    for report_item in acunetix_xml.findall('.//ReportItem'):
        report_items[report_item.attrib.get('id')] = {'name': report_item.find('Name').text,
                                                      'details': report_item.find('Details').text,
                                                      'severity': report_item.find('Severity').text,
                                                      'type': report_item.find('Type').text,
                                                      'description': report_item.find('Description').text,
                                                      'affects': report_item.find('Affects').text}
    return report_items


def print_vulns(vulns):
    """Print list of vulnerabilities to screen"""
    for v in vulns:
        if args.md5:
            m = hashlib.md5()
            m.update(vulns[v]['name'])
            md5 = m.hexdigest()
            print info + "[%s]\t%s (%s) " % (md5.upper(), vulns[v]['name'], vulns[v]['severity'])
        else:
            print info + "%s (%s)" % (vulns[v]['name'], vulns[v]['severity'])

        if args.verbose:
            print "\t" + info + "Vulnerable Path: %s" % vulns[v]['affects']
            print "\t" + note + "Type: %s" % vulns[v]['type']
            print "\t" + note + "Description: %s" % vulns[v]['description']
            print "\t" + note + "Details: %s" % vulns[v]['details']


def print_list(text, object):
    """Print list items to screen"""

    print info + "%s" % text
    for o in object:
        print "%s" % o


def parse_directory():
    """Parse all XML Files in directory"""

    files = None
    if os.path.isdir(os.path.expanduser(args.directory)):
        files = os.listdir(args.directory)

    if files is not None:
        for f in files:
            if f.lower().endswith('.xml'):
                parse_file(os.path.join(os.path.expanduser(args.directory), f))


def parse_file(f):
    """Parse a single file"""

    xml_file = open(f, "r")
    xml = parse(xml_file)
    acunetix_xml = xml.getroot()
    if args.verbose:
        print "XML Root TAG: %s" % acunetix_xml.tag
    # Check for valid Acunentix XML File
    if acunetix_xml.tag == "ScanGroup":
        if args.URL:
            urls = get_urls(acunetix_xml)
            print_list("Found URLS", urls)
        if args.directories:
            paths = get_paths(acunetix_xml)
            print_list("Found Paths", paths)
        if args.files:
            files = get_files(acunetix_xml)
            print_list("Found Files", files)
        if args.vulns:
            vulns = get_report_items(acunetix_xml)
            print_vulns(vulns)
    else:
        pass


if __name__ == '__main__':
    try:
        if args.xml:
            parse_file(args.xml.name)
        if args.directory:
            parse_directory()
    except KeyboardInterrupt:
        print "\nUser Interrupt! Quitting...."
    except:
        print "\nPlease report this error to " + __maintainer__ + " by email at: " + __email__
        raise