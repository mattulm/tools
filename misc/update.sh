#!/bin/bash

loggeropt="logger -t update -s"

#Ueberpruefung auf Updates

#History:
#08092007 - v0.01b: integration of the centos part from widi, apt/yum release integrated, small fixes -- tested on CentOS & Debian
#07092007 - v0.01a: some small fixes
#v0.1: $domainname integriert
#      MAILTO integriert
#      vorbereitungen fuer unterschiedliche Distris

release=v0.01b
domainname="m1k3.at"
MAILTO=root
debian=0
redhat=0

if [ -f /etc/debian_version ]; then     #gehoert noch auf ubuntu angepasst
        debian=1        # ein debiansystem
elif [ -f /etc/redhat-release ]; then
        redhat=1
else
        $loggeropt "es konnte keine unterstuetzte Distribution festgestellt werden "
fi


$loggeropt " "
$loggeropt "===================== `date +%F-%T` ====================="
$loggeropt "update ueberpruefung fuer `hostname`.$domainname wird gestartet"

if [ $debian -eq 1 ]; then  #debian-spezifisch
	rm /tmp/update* | tee -a /tmp/update
#        options="upgrade" | tee -a /tmp/update
        which apt-get | tee -a /tmp/update
        if [ $? -ne 0 ]; then
                $loggeropt " "
                $loggeropt "            ===================WARNING==================="
                $loggeropt "            auf diesem System befindet sich kein apt-get"
                $loggeropt "            ===================WARNING==================="
                $loggeropt " "
                exit 1
        fi

	echo -e "Verwendete APT-Version: `apt-get -v | grep "apt.*for linux.*compiled.*" | cut -d\  -f2`" | tee -a /tmp/update
	echo -e "apt Datenbank wird aktualisiert \n" | tee -a /tmp/update
        apt-get update | tee -a /tmp/update

        #bei englischen System gehoert "entfernen" gegen "remove" getauscht
	echo -e "\n Systemupgrade wird getestet:\n" | tee -a /tmp/update
        apt-get upgrade -s | tee -a /tmp/update

	apt-get upgrade -s | grep remove | $loggeropt `cut -d, -f1-3` | tee -a /tmp/update       #alles ausgeben!
        upgrade=`apt-get upgrade -s | grep remove | cut -d, -f1-3 | cut -d\  -f1`
        installing=`apt-get upgrade -s | grep remove | cut -d, -f1-3 | cut -d\  -f3`
        removing=`apt-get upgrade -s | grep entfernen | cut -d, -f1-3 | cut -d\  -f6`

elif [ $redhat -eq 1 ]; then
	echo "test6"
	which yum | tee -a /tmp/update
	if [ $? -ne 0 ]; then
                $loggeropt "            ===================WARNING==================="
                $loggeropt "            auf diesem System befindet sich kein yum"
                $loggeropt "            ===================WARNING==================="
        	exit 1
	fi

	echo -e "Verwendete Yum-Version: `yum --version`" | tee -a /tmp/update
	echo -e "YUM Datenbank wird aktualisiert \n" | tee -a /tmp/update
	yum check-update -d 5 | tee -a /tmp/update 	#just for the output in the logfile

	upgrade=`yum check-update -d 5 | grep -e ".*update\b" | wc -l | tee -a /tmp/update` 	#check how much packages we have to upgade
	if [ $upgrade -ne 0 ]; then
		#hier muessen die Anzahl der Pakete die evtl zusaetzlich installiert werden sollen in eine Variable ($installing) geschrieben werden
		#damit sie im Distributionsunabhaengigen Teil ausgewertet werden koennen, enbenso mit paketen die entfernt werden sollen
		installing=0
		removing=0
        	#$loggeropt " "
	        #$loggeropt " PAKETE ZUM UPDATEN VORHANDEN! "
        	#$loggeropt " "
	else
		upgrade=0
		installing=0
		removing=0
	        #$loggeropt " "
	        #$loggeropt " Keine Updates zum Einspielen "
	        #$loggeropt " "
	fi

fi

##distributionsunabhaengig
echo $upgrade
if [ $upgrade -gt 0 ]; then
echo -e "\n \n Scriptversion: '$release' \n \n
 ===================== `date +%F-%T` ===================== \n \
update ueberpruefung fuer `hostname`.$domainname \n \
\n \
===================WARNING=================== \n \
Es sollten $upgrade Pakete upgedated werden \n \
dabei werden $installing Pakete neu installiert \n \
und $removing Pakete entfernt \n \
===================WARNING=================== \n \
\n \
update ueberpruefung fuer `hostname`.$domainname \n \
===================== `date +%F-%T` ===================== \n \
\n \
Details entnehmen sie bitte der folgenden Ausgabe: \n"  > /tmp/update0

cat /tmp/update >> /tmp/update0
cat /tmp/update0 | mail -s "WARNING: Update - Output from `hostname`.$domainname" $MAILTO
rm -rf /tmp/update*

else
        $loggeropt "Es muessen KEINE kritischen Updates eingespielt werden" # | mail -s "Info: Update - Output" $MAILTO
fi

$loggeropt "update ueberpruefung fuer `hostname`.$domainname wurde durchgefuehrt"
$loggeropt "===================== `date +%F-%T` ====================="
$loggeropt " "

exit 0

