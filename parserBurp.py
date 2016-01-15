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


def parse(xml_file):
    """Parse XML file and return ElementTree object"""
    if args.verbose or args.directory:
        print note + str(xml_file)
    xml_tree = ElementTree.parse(xml_file)

    return xml_tree


def parse_file(f):
    """Parse a single file"""

    xml_file = open(f, "r")
    xml = parse(xml_file)
    burp_xml = xml.getroot()
    if args.verbose:
        print "XML Root TAG: %s" % burp_xml.tag
    # Check for valid Burp XML File
    if burp_xml.tag == "issues":
        return burp_xml
    else:
        print warn + "Note a valid Burp XML file!"
        return None


def get_paths(burp_xml):
    """Parse a list of found directories and file names"""

    urls = []  # A list to hold all discovered paths

    for site_files in burp_xml.find('.//SiteFiles'):
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


def print_list(text, object):
    """Print list items to screen"""

    print info + "%s" % text
    for o in object:
        print "%s" % o


def print_vulns(vulns):
    """Print list of vulnerabilities to screen"""
    for v in vulns:
        if args.md5:
            m = hashlib.md5()
            m.update(vulns[v]['name'])
            md5 = m.hexdigest()
            print info + "[%s]\t%s (%s - %s) " % (md5.upper(), vulns[v]['name'], vulns[v]['severity'],
                                                  vulns[v]['confidence'])
        else:
            print info + "%s (%s - %s)" % (vulns[v]['name'], vulns[v]['severity'], vulns[v]['confidence'])

        if args.verbose:
            print "\t" + info + "Host: %s (%s)" % (vulns[v]['host_name'], vulns[v]['host_ip'])
            print "\t" + info + "Vulnerable Path: %s" % vulns[v]['path']
            print "\t" + info + "Vulnerable Location: %s" % vulns[v]['location']
            print "\t" + info + "Type: %s" % vulns[v]['type']

        if args.vverbose:
            print "\t" + note + "Description: %s" % vulns[v]['issueBackground']
            print "\t" + note + "Request: %s" % vulns[v]['request']['data']
            print "\t" + note + "Response: %s" % vulns[v]['response']['data']


def get_files(burp_xml):
    """Get a sorted list of all discovered files"""
    files = []  # A list to hold all discovered files
    for site_files in burp_xml.find('.//SiteFiles'):
        for site_file in site_files:
            f = site_files.find('./URL')
            if "." in f.text:
                files.append(str(f.text).strip('%20'))

    return sorted(set(files), key=str.lower)


def parse_directory():
    """Parse all XML Files in directory"""

    files = None
    if os.path.isdir(os.path.expanduser(args.directory)):
        files = os.listdir(args.directory)
        return files


def get_report_items(burp_xml):
    """Get Burp report findings"""

    report_items = {}

    for report_item in burp_xml.findall('.//issue'):
        report_items[report_item.find('serialNumber')] = {'name': report_item.find('name').text,
                                                          'type': report_item.find('type').text,
                                                          'host_name': report_item.find('host').text,
                                                          'host_ip': report_item.find('host').attrib['ip'],
                                                          'path': report_item.find('path').text,
                                                          'location': report_item.find('location').text,
                                                          'severity': report_item.find('severity').text,
                                                          'confidence': report_item.find('confidence').text,
                                                          'issueBackground': report_item.find('issueBackground').text,
                                                          'remediationBackground': report_item.find('remediationBackground').text,
                                                          'request': {'method': None, 'base64': None, 'data': None},
                                                          'response': {'base64': None, 'data': None}
                                                          }

        report_items[report_item.find('serialNumber')]['request']['data'] = report_item.find('requestresponse/request').text
        report_items[report_item.find('serialNumber')]['request']['method'] = report_item.find('requestresponse/request').attrib['method']
        report_items[report_item.find('serialNumber')]['request']['base64'] = report_item.find('requestresponse/request').attrib['base64']

        report_items[report_item.find('serialNumber')]['response']['data'] = report_item.find('requestresponse/response').text
        report_items[report_item.find('serialNumber')]['response']['base64'] = report_item.find('requestresponse/response').attrib['base64']
    return report_items


def transform_report(vulns):
    """Transform dictionary to format that can be used for generating reports"""

    report = {}

    for v in vulns:
        if vulns[v]['name'] not in report.keys():
            report[vulns[v]['name']] = [(vulns[v]['host_name'],vulns[v]['location'])]
        else:
            if (vulns[v]['host_name'],vulns[v]['location']) not in report[vulns[v]['name']]:
                report[vulns[v]['name']].append((vulns[v]['host_name'],vulns[v]['location']))

    return report


def standalone():
    """Run Burp Suite Parser as standalone script"""

    # TODO change handling so it is the same after single file or directory selected
    if args.xml:
        burp_file = parse_file(args.xml.name)

        if burp_file is not None:
            vulns = get_report_items(burp_file)
        if args.vulns or args.md5:
            print_vulns(vulns)
        if args.listing:
            report = transform_report(vulns)
            for r in report:
                print info + "%s" % r
                for i in report[r]:
                    print "\t" + note + " %s%s" %(i[0], i[1])

    if args.directory:
        files = parse_directory()
        if files is not None:
            for f in files:
                if f.lower().endswith('.xml'):
                    burp_file = parse_file(os.path.join(os.path.expanduser(args.directory), f))
                    if burp_file is not None:
                        vulns = get_report_items(burp_file)
                    if args.vulns or args.md5:
                        print_vulns(vulns)
                    if args.listing:
                        report = transform_report(vulns)
                        for r in report:
                            print info + "%s" % r
                            for i in report[r]:
                                print "\t" + note + " %s%s" %(i[0], i[1])


if __name__ == '__main__':
    try:

        # Parse command line arguments
        parser = argparse.ArgumentParser()
        file_group = parser.add_mutually_exclusive_group(required=True)
        file_group.add_argument('-X', '--xml', type=argparse.FileType('r'), help="Brup Suite XML file")
        file_group.add_argument('-D', '--directory', help="Parse all XML files in directory")


        parser.add_argument('-V', '--vulns', action='store_true', default=False, help="List found vulnerabilities. Default=True")
        parser.add_argument('-m', '--md5', action='store_true', default=False, help="Print MD5 hash of vulnerability")
        parser.add_argument('-v', '--verbose', action='store_true', default=False, help="Verbose Output")
        parser.add_argument('-vv', '--vverbose', action='store_true', default=False, help="More Verbose Output to include HTTP Request and Response")
        parser.add_argument('-l', '--listing', action='store_true', default=False, help="Vulnerability Listing by Vulnerability")
        args = parser.parse_args()

        standalone()

    except KeyboardInterrupt:
        print "\nUser Interrupt! Quitting...."
    except:
        print "\nPlease report this error to " + __maintainer__ + " by email at: " + __email__
        raise