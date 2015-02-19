#!/bin/bash

#PROGRAM BY ERIC MARSHOTT
#this is to be used on ubuntu machine in BASH shell
#tested in ubuntu10.04
#internet connection will be tested before continuing with script
#then nmap is checked with dpkg manager to see if it is installed
#it is asked if you want to see man page...if yes you will see first 175 lines of man page
#various nmap commands are provided with options 1-6


if [ $EUID -ne 0 ]
then echo "this script must be run as root"
echo "Your userid is $EUID"; exit
else echo "Your userid is $EUID"
fi
echo -e "\nI am checking to see if you have internet connection...\n"
externalIP=$(wget -T 5 -O - -o /dev/null http://myip.dnsomatic.com)
if [ $? -ne 0 ]
then
echo -e "\nIt looks like you don't have internet connectivity...\n\nGet a connection and try me again!"; exit
fi

defaultInterface=$(ip r | grep 'default' | awk '{print $5}')

localIP=$(ip r | grep 'default' | awk '{print $3}')

localsubnet=$(ip r | grep $defaultInterface | awk '{print $1}' | sed q)

echo -e "\nYour externalIP is: $externalIP"
echo -e "\nYour internalIP is: $localIP"
echo -e "\n"

nmapinstalled=$(dpkg -s nmap | grep installed )
echo -e "Checking for nmap install in dpkg: $nmapinstalled\n"
if [ "" == "$nmapinstalled" ]; then
	echo -e "Nmap does not seem to be installed, trying to install now\n"
	read -p "Install nmap and continue with script? " nmapyes
	case $nmapyes in
		[Yy] ) apt-get install nmap; break;;
		* ) echo -e "\nthat's a no...exiting script"; exit;;
	esac
fi

echo -e "NMAP will give you the ability to scan for open ports...\n\n"
read -p "Would you like to see the man page?" seeman
	case $seeman in
	[Yy]* ) man nmap | head -n 175;;
	* ) echo -e "\nOkay, lets get to the nmap shindig...\n\n";;
	esac


echo -e "\nPlease choose the type of scan you would like to perform on your system:\n"
echo -e "1) Check which ports are listening on \nyour default gateway(router)."
echo -e "2) Check which popular ports are publicly accessible \nto your internet gateway."
echo -e "3) Check if a webserver is listening on your public IP"
echo -e "4) Check common open ports on another computer"
echo -e "5) Scan your local subnet"
echo -e "6) Fast scan of your loopback adapter"

echo -e "\n"
quitter="3"
for (( c=1; c>=1; c-- ))
do
if [ $quitter -eq 0 ]
then
echo -e "\nIt sounds to me like we're having input problems....run my program again."; exit;
fi

read -p "Enter your choice and press enter..." entry

case $entry in
	[1] ) nmap -PNn -T aggressive $localIP ;
;;
	[2] ) nmap -PNn -F $externalIP ;
;;
	[3] ) nmap -PNn -p 80 $externalIP ;
;;
	[4] ) echo -e "\nEnter hostname/IP:"; read host; echo "This may take a while..."; nmap -PN -T normal -F $host ;
;;
	[5] ) echo -e "This may take a while..."; nmap -PNn $localsubnet ;
;;
	[6] ) nmap -T aggressive localhost
;;
	*) echo -e "\nWrong entry please try again\n"; c=$[$c+1]; quitter=$[$quitter-1];
;;
esac
done

echo -e "\nThank you for using my program, goodbye\n"
