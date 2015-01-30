#!/bin/bash

#This is a script to record terminal sessions to a file
#Create an alias to increase effectivness add to /etc/bash.bashrc or /<user>/.bashrc
#i.e. alias record="sh /opt/record.sh"


#MAIN


#Make sure two arguments were recieved
if [ $# -lt 2 ]; then
	echo "USAGE: script <client> <location>"
	exit
fi

#Check if help was request
if [ "$1" = "-h" ]; then
	echo "USAGE: script <client> <location>"
	exit
fi

echo -e '\033[0;0;37m'" TERMINAL RECORDING STARTED FOR $1" '\033[0m'

script -f "$2SHELL-LOG_$1_$(date +"%d-%b-%y_%H-%M-%S")_$(date | md5sum | head -c8).log"
