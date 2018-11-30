# parserBloodHound.py

This script is used to parse an individual BloodHound 2.0 JSON file to generate a CSV containing a list of hosts where remote group membership was enumerated. This is used when reporting the Authenticated Remote SAMR Enumeration vulnerability.

# record.sh

This script is used to record a terminal session to a file that can later be viewed. The script takes to two arguments, a unique name (such as a client's name) and the directory to save the file. Create an alias in /etc/bash.bashrc or /<user>/.bashrc to quickly call this script (i.e. alias record="sh /opt/record.sh"). 

```USAGE: script <client> <location>```
 ```Example: record ClientA /root/Desktop/```
---
