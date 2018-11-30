#! /usr/bin/env python

# Make sure to convert the BloodHound JSON file with dos2unix before using with this script

#################################################
#                    Imports                    #
#################################################
import os
import argparse
import json

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


def parse_json_file_to_dictionary(filename):
    """Parse an input JSON file object into a python dictionary object and return it"""

    if DEBUG:
        print debug + "Entering parse_json_file_to_dictionary function"
    try:
        if os.path.isfile(filename.name):
            if DEBUG:
                print debug + "the file %s does exist" % filename
            json_data = filename.read()
            try:
                data = json.loads(json_data)
            except ValueError:
                print warn + "There was a ValueError parsing the provided file"
                print info + "Try converting the file with dos2unix <filename>"
                print info + "apt install dos2unix"
                raise
            return data
        else:
            print warn + "%s is not a valid file, it does not exist"
    except TypeError:
        print warn + "There was TypeError in the parse_json_file_to_dictionary function"
        raise
    except:
        raise


def get_bloodhound_metrics():
    """Get metrics for provided Bloodhound"""
    
    d = {}

    j = parse_json_file_to_dictionary(args.json)

    if "computers" in j:
        parse_computers(j)
    elif "sessions" in j:
        parse_sessions(j)
    else:
        print warn + "JSON file did not contain a computers or session object"


# Used to get a list of hosts affected by the Authenticated Remote SAMR vulnerability

def parse_computers(json_data):
    """Parse a JSON file containing a computers object from BloodHound"""

    
    computers = len(json_data["computers"])
    computersWithGroups = 0 # Any computer object where remote group membership was enumerated
    localAdmins = 0
    remoteDesktopUsers = 0
    dcomUsers = 0

    print info + "Parsing BloodHound COMPUTERS JSON object"

    if DEBUG:
        print debug + "Computer object JSON dictionary keys"
        print json_data.keys()

    if args.csv:
        print '"Name","LocalAdmins","RemoteDesktopUsers","DcomUsers"'
    
    for computer in json_data["computers"]:

       a = 0 # LocalAdmins
       r = 0 # RemoteDesktopUsers
       d = 0 # DcomUsers

       if DEBUG:
           print debug + "JSON dictionary keys"
           print computer.keys()

       if "LocalAdmins" in computer:
           if computer["LocalAdmins"] is not None:
               a = len(computer["LocalAdmins"])
               localAdmins += a
       if "RemoteDesktopUsers" in computer:
           if computer["RemoteDesktopUsers"] is not None:
               r = len(computer["RemoteDesktopUsers"])
               remoteDesktopUsers += r
       if "DcomUsers" in computer:
           if computer["DcomUsers"] is not None:
               d = len(computer["DcomUsers"])
               dcomUsers += d

       total = a + r + d

       if total > 0:
           computersWithGroups += 1
           if "Name" in computer and args.csv:
               print '"%s","%d","%d","%d"' % (computer["Name"], a, r, d)

    print info + "Total computers where local groups were remotely enumerated: %d" % computersWithGroups


def parse_sessions(json_data):
    """Parse a JSON file containing a sessions object from BloodHound"""
    
    computers = {}

    print info + "Parsing BloodHound SESSIONS JSON object"
      
    for session in json_data["sessions"]:
        if "ComputerName" in session:
            if session["ComputerName"] in computers:
                computers[session["ComputerName"]] += 1
            else:
                computers[session["ComputerName"]] = 1
    if computers is not None and args.csv:
        print '"Name","Sessions"'
        for computer in computers:
            print '"%s","%d"' % (computer, computers[computer])
    
    print info + "Total computers with a session: %d" % len(computers)


if __name__ == '__main__':
    """Main function for parsing a BloodHound JSON file"""

    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json', type=argparse.FileType('r'), required=True,
                        help="JSON file to parse for metrics")
    parser.add_argument('--csv', action='store_true', default=False, help="Write results to STDOUT in CSV format")
    parser.add_argument('--verbose', action='store_true', default=False, help="Enable verbose output")
    parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output")
    args = parser.parse_args()

    DEBUG = args.debug
    VERBOSE = args.verbose

    try:
        if not args.json:
            parser.print_help()
            exit
        if args.json:
            get_bloodhound_metrics()
    except KeyboardInterrupt:
        print "\n" + warn + "User Interrupt! Quitting...."
    except SystemExit:
        pass
    except:
        print "\n" + warn + "Please report this error to " + __maintainer__ + " by email at: " + __email__
        raise
