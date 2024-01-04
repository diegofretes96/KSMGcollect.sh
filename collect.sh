#!/bin/sh
Edition='HQ-basic'
Version='2023-09-19'
TMP=/tmp/collect
# Temp folder for collect contents and _must not_ exist.
# Report itself will be created under /tmp or $TMP/../ and _must_ exist.


SYSTEM_TYPE=$(uname | tr [:lower:] [:upper:])
HOST_NAME=$(hostname | tr [:upper:] [:lower:])
ERROR=0


if [ $(id -u) -ne 0 ]; then
	echo "This script requires root privileges in order to run!"
	ERROR=1
else

	echo "
	----------------------------------------------------------------------------
	This script collects various system information about your linux/unix/mac host.
	This information is important for Kaspersky Support service.
	You would find the result at /tmp/%hostname%-collect.tar.gz
	
	PLEASE REMOVE EVERYTHING YOU CONSIDER CONFIDENTIAL BEFORE SENDING
	
	To find out what is collected you can open this script in a text editor and 
	read its comments.
	
	By continuing you agree to the End User License Agreement in license.rtf file
	which is distributed in the same archive with this script.
	
	Press [y] and [Enter] keys if you accept the End User License Agreement.
	----------------------------------------------------------------------------
	"
	read eula
	if [ "$eula" != "y" ]; then
	   echo "Must agree with EULA."
	   exit 1
	fi

	mkdir $TMP
	if [ $? -ne 0 ]; then
		echo "Could not create target directory. Must specify non-existing folder under existing path"
		exit 1
	fi
    # Log all error during execution to clog
	exec 6>&2
	exec 2> $TMP/clog

	echo "Script version" $Edition $Version
	echo $Version > $TMP/HQ-basic-version

	echo -n "free space pre-check:" | tee -a $TMP/clog
	df -h $TMP | tail -n 1 | awk '{print " "$4" available in "$6" mount point"}'

	echo "collecting environment..." | tee -a $TMP/clog

	TMPE=$TMP/environment
	mkdir $TMPE
	# Save environment variables
	set > $TMPE/set.txt
	env > $TMPE/env.txt

	TMPK=$TMP/kaspersky
	mkdir $TMPK

	if [ "$SYSTEM_TYPE" = "DARWIN" ]; then
		# list jobs loaded into launchd
		launchctl list > $TMPE/launchctl.txt
		# get current memory usage information
		memory_pressure > $TMPE/memory.txt
		# list all mounts
		mount > $TMPE/hdd.txt
		# get free space on mounted file systems
		df -h >> $TMPE/hdd.txt
		# get free inodes on mounted file systems
		df -hi >> $TMPE/hdd.txt
		# diskutil
		diskutil info -all > $TMPE/diskutil.txt
		# get groups
		cp /etc/group $TMPE/group
		# list processes
		ps -ef > $TMPE/ps.txt
		# list processes
		top -l 1 > $TMPE/top.txt
		# OS/kernel version
		uname -a >> $TMPE/uname.txt
		# kernel parameters
		sysctl -a > $TMPE/sysctl.txt
		# currently open files
		lsof > $TMPE/lsof.txt
		# virtual memory statistics
		vm_stat > $TMPE/vmstat.txt
		# IO statistics
		iostat > $TMPE/iostat.txt
		# user limits
		ulimit -a > $TMPE/ulimit.txt
		# routing information
		netstat -nr > $TMPE/route.txt
		# network interfaces
		ifconfig > $TMPE/ifconfig.txt
		# time system running
		uptime > $TMPE/uptime.txt
		# hostname
		hostname -f > $TMPE/hostname.txt
		# hosts file
		cp /etc/hosts $TMPE
		# DNS configuration
		cp /etc/resolv.conf $TMPE
		# scheduled scripts
		cp -R /etc/periodic/ $TMPE
		# current time
		date > $TMPE/date.txt
		# check internet availability
		ping -c2 support.kaspersky.com > $TMPE/ping.txt
		# loaded kernel extensions
		kextstat > $TMPE/kextstat.txt
		# system hardware and software configuration
		system_profiler -detailLevel full -xml > $TMPE/system.spx
		# get status of Kaspersky components
		(kav status > $TMPK/kav_status.txt) & sleep 10 ; kill $! #limit the execution time as kav hangs from time to time
		# get product configuration file
		cp /Library/Application\ Support/Kaspersky\ Lab/KAV/Binaries/config.xml $TMPK/config.xml
		# Check Kaspersky Network Agent configuration
		/Library/Application\ Support/Kaspersky\ Lab/klnagent/Binaries/klnagchk > $TMPK/klnagchk.txt
		# copy KLNagent - product connectors 
		mkdir $TMPK/connectors
		cp -R /Library/Application\ Support/Kaspersky\ Lab/klnagent_conf/connectors.d/ $TMPK/connectors
		cp -R /Library/Application\ Support/Kaspersky\ Lab/klnagent_conf/connectors64.d/ $TMPK/connectors
		PRODVERSION=`ls $TMPK/connectors`
		grep ProductHotfix /Library/Application\ Support/Kaspersky\ Lab/KAV/Data/blregistry.xml | awk '{print $2}' >> $TMPK/connectors/$PRODVERSION
		# list subdirecories of /Users
		dscl . list /Users | grep -v -e '^_' > $TMPE/users.txt
		# is user consent needed to install kernel extensions?
		spctl kext-consent status > $TMPE/kext_consent.txt
		# get current policy for kernel extensions (list kernel extensions that were allowed by user)
		sqlite3 -separator $'\t' -header /var/db/SystemPolicyConfiguration/KextPolicy "select * from kext_policy" > kext_policy.txt
		# get sudo security policy configuration
		cp /etc/sudoers $TMPE/sudoers.txt
		# get SSHD and systemd configuration options - for remote installation troubleshooting
		grep 'PasswordAuthentication\|ChallengeResponseAuthentication' /etc/ssh/sshd_config > $TMPE/klnagent.remote.txt
		grep 'KillUserProcesses\|KillExcludeUsers' /etc/systemd/logind.conf >> $TMPE/klnagent.remote.txt
		# OS version
		sw_vers > $TMPE/os_release.txt
		# list system extensions
		systemextensionsctl list > $TMPE/systemextensionsList.txt


	elif [ "$SYSTEM_TYPE" = "LINUX" ]; then
		# get systemd services information
		systemctl --full --all > $TMPE/systemctl.txt
		# hardware configuration
		lshw > $TMPE/lshw.txt
		# detailed CPU information
		cat /proc/cpuinfo > $TMPE/cpuinfo.txt
		# memory usage
		free -h > $TMPE/memory.txt
		# list mounts
		mount > $TMPE/hdd.txt
		# get free space on mounted file systems
		df -h >> $TMPE/hdd.txt
		# get free inodes on mounted file systems
		df -hi >> $TMPE/hdd.txt
		# get list of system users (no passwords included)
		cp /etc/passwd $TMPE/passwd
		# get list of system groups
		cp /etc/group $TMPE/group
		# process list
		ps axo state,pid,ppid,tid,pcpu,pmem,rsz,vsz,cmd > $TMPE/ps.txt
		ps axo state,pid,ppid,tid,pcpu,pmem,rsz,vsz,cmd -T > $TMPE/pst.txt
		pstree > $TMPE/pstree.txt
		top -b -n 1 > $TMPE/top.txt
		top -bH -n 1 > $TMPE/toph.txt
		# OS issue text (normally version)
		cat /etc/issue >$TMPE/uname.txt
		# kernel version information
		uname -a >> $TMPE/uname.txt
		# OS issue and release text (normally version)
		ls /etc/issue /etc/*release > $TMPE/os_release.txt
		cat /etc/issue /etc/*release >> $TMPE/os_release.txt
		# kernel parameters
		sysctl -a > $TMPE/sysctl.txt
		# SELinux status
		sestatus > $TMPE/sestatus.txt
		cp /etc/selinux/config	$TMPE/seconfig.txt
		# AppArmor status
		apparmor_status > $TMPE/app_armor.txt
		# loaded kernel modules
		lsmod > $TMPE/lsmod.txt
		# currently open files
		lsof -n > $TMPE/lsof.txt
		# inter-process communication status (active message queues, semaphore sets, shared memory segments)
		ipcs -a > $TMPE/ipcs.txt
		# virtual memory statistics
		vmstat 1 10 > $TMPE/vmstat.txt & vmstat -d 1 10 > $TMPE/vmstatd.txt & vmstat -m 1 10 > $TMPE/vmstatm.txt & iostat -xk 1 10 > $TMPE/iostat.txt
		# disk statistics
		vmstat -D > $TMPE/vmstatd2.txt
		# memory statistics
		vmstat -s > $TMPE/vmstats.txt
		# list installed rpm packages
		rpm -qa >> $TMPE/packages.txt
		# list installed dpkg packages
		dpkg -l >> $TMPE/packages.txt
		# python/python3 version
		echo "python --version: " > $TMPE/pythonvers.txt
		python --version >> $TMPE/pythonvers.txt
		echo "python3 --version: " >> $TMPE/pythonvers.txt
		python3 --version >> $TMPE/pythonvers.txt
		# pip3 packages
		pip3 list > $TMPE/pip3list.txt
		# user limits
		ulimit -a > $TMPE/ulimit.txt
		# systemd dumps listing
		coredumpctl list > $TMPE/coredumps.txt
		ls -la /var/lib/systemd/coredump >> $TMPE/coredumps.txt
		# routing information
		route -n > $TMPE/route.txt
		# network interfaces
		ifconfig >$TMPE/ifconfig.txt
		# network interfaces
		ip a > $TMPE/ipa.txt
		# network connections info
		netstat -apln > $TMPE/netstat.txt
		# list sockets
		ss -npatu > $TMPE/ss.txt
		# routing tables and rules
		ip -4 route ls > $TMPE/ipv4routes.txt
		ip -4 rule ls > $TMPE/ipv4rules.txt
		ip -6 route ls > $TMPE/ipv6routes.txt
		ip -6 rule ls > $TMPE/ipv6rules.txt
		# list iptables firewall rules
		iptables -L > $TMPE/iptables.txt
		iptables -nvL -t filter > $TMPE/iptables-filter.txt
		iptables -nvL -t mangle > $TMPE/iptables-mangle.txt
		iptables -nvL -t nat > $TMPE/iptables-nat.txt
		ip6tables -L > $TMPE/ip6tables.txt
		ip6tables -nvL -t filter > $TMPE/ip6tables-filter.txt
		ip6tables -nvL -t mangle > $TMPE/ip6tables-mangle.txt
		ip6tables -nvL -t nat > $TMPE/ip6tables-nat.txt
		# list firewalld zones
		firewall-cmd --list-all-zones > $TMPE/firewalld.zones.txt
		# time system running, load average
		uptime > $TMPE/uptime.txt
		# get hostname
		hostname > $TMPE/hostname.txt
		# get hosts file
		cp /etc/hosts $TMPE
		# DNS resolver configuration
		cp /etc/resolv.conf $TMPE
		# get Cron scheduled scripts
		cp -RL /etc/cron.d/ $TMPE
		cp -RL /etc/cron.daily/ $TMPE
		cp -RL /etc/cron.weekly/ $TMPE
		cp -RL /etc/cron.monthly/ $TMPE
		cp -RL /etc/cron.hourly/ $TMPE
		cp -R /etc/rsyslog.d/ $TMPE
		# rsyslog logging configuration
		cp /etc/rsyslog.conf $TMPE
		mkdir $TMPE/mta
		mkdir $TMPE/mta/postfix
		mkdir $TMPE/mta/sendmail
		# audit rules export
		mkdir $TMPE/audit
		cp /etc/audit/auditd.conf $TMPE/audit
		cp /etc/audit/audit.rules $TMPE/audit
		cp -R /etc/audit/rules.d $TMPE/audit/rules.d
		# get postfix configuration files
		cp /etc/postfix/*.cf $TMPE/mta/postfix/
		cp /etc/postfix/header_checks $TMPE/mta/postfix/
		# get sendmail configuration files
		cp /etc/mail/*.cf $TMPE/mta/sendmail/
		cp /etc/mail/*.mc $TMPE/mta/sendmail/
		# get exim configuration files
		cp -R /etc/exim4 $TMPE/mta/
		# crontab scheduled scripts
		cp /etc/crontab $TMPE
		# get listing of system directories
		ls -la / /tmp /opt /var /etc /usr > $TMPE/lsroot.txt
		# get recursive listing of product directories
		ls -laR /opt/kaspersky /var/opt/kaspersky > $TMPE/lskasp.txt
		# get listing of system libs
		ls -la / /usr | grep lib > $TMPE/lslib.txt
		ls -laL /lib* >> $TMPE/lslib.txt
		ls -laL /usr/lib* >> $TMPE/lslib.txt
		# get current time
		date > $TMPE/date.txt
		LC_ALL=en_EN.utf8  date > $TMPE/date_en.txt
		# check if internet is available
		ping -c2 support.kaspersky.com > $TMPE/ping.txt
		# get sudo security policy configuration
		cp /etc/sudoers $TMPE/sudoers.txt
		# are filesystem wide access notifications enabled in kernel
		grep CONFIG_FANOTIFY /boot/config-$(uname -r) > $TMPE/fanotify.txt
		# get SSHD and systemd configuration options - for remote installation troubleshooting
		grep 'PasswordAuthentication\|ChallengeResponseAuthentication' /etc/ssh/sshd_config > $TMPE/klnagent.remote.txt
		grep 'KillUserProcesses\|KillExcludeUsers' /etc/systemd/logind.conf >> $TMPE/klnagent.remote.txt
		# Samba config
		testparm -s > $TMPE/smb.conf
		
		# OS specific
		cat /sys/digsig/elf_mode > $TMPE/astrazps.txt
		cat /sys/digsig/xattr_mode >> $TMPE/astrazps.txt

		# Kaspersky product related stuff
			# various product configuration files
			cp -RL /etc/opt/kaspersky  $TMPK/etc
			cp -R /var/opt/kaspersky/lmc-agent $TMPK/
			cp -R /var/opt/kaspersky/lmc-server $TMPK/
			
			# Check Kaspersky Network Agent configuration
			/opt/kaspersky/klnagent/bin/klnagchk -tl 5 -savecert $TMPK/klnagchk-cert  > $TMPK/klnagchk.txt
			cat $TMPK/klnagchk-cert | openssl x509 -text -noout > $TMPK/klnagchk-certinfo.txt
			/opt/kaspersky/klnagent64/bin/klnagchk -tl 5 -savecert $TMPK/klnagchk64-cert > $TMPK/klnagchk64.txt
			cat $TMPK/klnagchk64-cert | openssl x509 -text -noout > $TMPK/klnagchk64-certinfo.txt
			cp /var/opt/kaspersky/klnagent/log/\$klnagchk-klnagchk.log $TMPK
			systemctl status klnagent > $TMPK/klnagent_ctlstatus.txt
			systemctl cat klnagent > $TMPK/klnagent_ctlcat.txt
			journalctl -xu "klnagent*" > $TMPK/journalnagent.txt
			
			# KSC version
			kscver=$(/opt/kaspersky/klnagent64/sbin/klscflag -ssvget -pv klnagent -s KLNAG_GLOBAL_SRVDATA_SECTION -n KLNAG_GLB_SRVDATA_SERVER_VERSION -ss "|ss_type = \"SS_GLBHST_PH\";" | egrep -o 'KLNAG_GLB_SRVDATA_SERVER_VERSION = \(INT_T\)[0-9]*')
			echo $kscver > $TMPK/klnagent_kscver.txt
			kscver=$(echo $kscver | egrep -o '[0-9]+')
			if [ $? -eq 0 ]; then
			echo $(($kscver/65536)).$(($kscver%65536/256)).$(($kscver%256)) >> $TMPK/klnagent_kscver.txt
			fi

			# Copy KSC, nagent and remote install logs
			cp /tmp/*_install_script.log $TMPK
			cp /tmp/klnagent*.log $TMPK
			cp /tmp/kesl*.log $TMPK
			cp /tmp/kics*.log $TMPK
			cp /tmp/kess*.log $TMPK
			cp /tmp/akinstall*.log $TMPK
			cp /opt/kaspersky/klnagent64/sbin/*.log $TMPK/
		# KLMS
			# KLMS setup script choices
			cat /var/opt/kaspersky/klms/installer.dat | grep -v installation_id > $TMPK/installer.dat
			# postgres configuration file 
			cp /var/opt/kaspersky/klms/postgresql/postgresql.conf $TMPK/
			# KLMS settings export
			/opt/kaspersky/klms/bin/klms-control --export-settings -f $TMPK/klms8set.xml
			# KLMS rules export
			/opt/kaspersky/klms/bin/klms-control --export-rules -f $TMPK/klms8rules.xml
			# KLMS licenses
			/opt/kaspersky/klms/bin/klms-control -l --get-installed-keys > $TMPK/klms8.lic
			# KLMS dashboard statistics
			/opt/kaspersky/klms/bin/klms-control --dashboard --month > $TMPK/klms8.stats
			# gather sendmail utility information
			cp /opt/kaspesrky/klms/bin/sendmail $TMPK/
			SENDMAIL=$(which sendmail)
			echo "$SENDMAIL" >> $TMPK/lms-sm
			ls -l "$SENDMAIL" >> $TMPK/lms-sm
			ls -l /etc/alternatives >> $TMPK/lms-sm
			ls -l /opt/kaspesrky/klms/bin/sendmail >> $TMPK/lms-sm
		# KESL
		if [ $(grep kesl $TMPE/packages.txt | wc -l) -ne 0 ]; then
			mkdir $TMPK/KESL
			# KESL service status
			systemctl status kesl > $TMPK/KESL/ctlstatus.txt
			systemctl cat kesl > $TMPK/KESL/ctlcat.txt
			journalctl -xu "kesl*" > $TMPK/KESL/journalkesl.txt
			# copy events database
			cp /var/opt/kaspersky/kesl/events.db $TMPK/KESL/
			cp /var/opt/kaspersky/kesl/private\ storage/events.db $TMPK/KESL/
			cp /var/opt/kaspersky/kesl/install-current/var/opt/kaspersky/kesl/private/storage/events.db $TMPK/KESL/
			# general KESL application information
			/opt/kaspersky/kesl/bin/kesl-control --app-info > $TMPK/KESL/appinfo.txt
			# non-root permission checker
			echo "Dir check:" >> $TMPK/KESL/rootperm.txt
			ls -lLd / /var /var/opt /var/opt/kaspersky /opt /opt/kaspersky /opt/kaspersky/klnagent64 /opt/kaspersky/klnagent64/sbin /opt/kaspersky/klnagent64/sbin/klnagent /usr /usr/lib64 /usr/bin/kesl-control | egrep -v '^.{5}-.{2}-.*root *root' >> $TMPK/KESL/rootperm.txt
			echo "kesl libs:" >> $TMPK/KESL/rootperm.txt
			for d in $(cat /proc/$(pidof -s kesl)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KESL/rootperm.txt
			echo "kesl-gui libs:" >> $TMPK/KESL/rootperm.txt
			for d in $(cat /proc/$(pidof -s kesl-gui)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KESL/rootperm.txt
			echo "nagent libs:" >> $TMPK/KESL/rootperm.txt
			for d in $(cat /proc/$(pidof -s klnagent)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KESL/rootperm.txt
			echo "connection errors:" >> $TMPK/KESL/rootperm.txt
			(kesl-control -E --query "EventType=='RemoteConnectionRejected'" | egrep "RemoteConnectionRejected|Reason|Path|Process" | sort --unique) >> $TMPK/KESL/rootperm.txt 2>&1
			echo "Process|Reason|Path" >> $TMPK/KESL/rootperm.txt
			sqlite3 $TMPK/KESL/events.db 'SELECT DISTINCT Process, Reason, Path FROM events WHERE EventType=134;' >> $TMPK/KESL/rootperm.txt
			# KESL license
			/opt/kaspersky/kesl/bin/kesl-control -L --query > $TMPK/KESL/license.txt
			# KESL settings export
			/opt/kaspersky/kesl/bin/kesl-control --export-settings > $TMPK/KESL/expset.txt
			/opt/kaspersky/kesl/bin/kesl-control --get-app-set > $TMPK/KESL/appset.txt
			/opt/kaspersky/kesl/bin/kesl-control --get-net-set > $TMPK/KESL/netset.txt
			# KESL task list
			/opt/kaspersky/kesl/bin/kesl-control --get-task-list > $TMPK/KESL/tasklist.txt
			# KESL task settings
			for i in $(kesl-control --get-task-list | egrep '(ID|Идентификатор)' | awk '{print $3}'); do echo 'TaskID '$i $(kesl-control --get-task-list | grep -w -B1 $i | egrep '(Name|Имя|Nom)' | awk '{print $2}') 'configuration:' >> $TMPK/KESL/taskset$i.txt; kesl-control --get-settings $i >> $TMPK/KESL/taskset$i.txt; printf '\n' >> $TMPK/KESL/taskset$i.txt; cat $TMPK/KESL/taskset$i.txt >> $TMPK/KESL/taskset.all.txt; done
			# KESL host Device list, App list
			/opt/kaspersky/kesl/bin/kesl-control --get-device-list > $TMPK/KESL/devlist.txt
			/opt/kaspersky/kesl/bin/kesl-control --get-app-list > $TMPK/KESL/applist.txt
			# KESL update log
			/opt/kaspersky/kesl/bin/kesl-control -E --query "TaskType == 'Update'" > $TMPK/KESL/updateLog.txt
			# get recursive listing of product directory
			ls -la /var/opt/kaspersky/kesl > $TMPK/KESL/listing.txt
			find /var/opt/kaspersky/kesl/ >> $TMPK/KESL/listing.txt
			# various configs of interest
			cp /var/opt/kaspersky/kesl/private/exported_settings.ini $TMPK/KESL/
			cp /var/opt/kaspersky/kesl/private/storage/appSettings.xml $TMPK/KESL/
			cp /var/opt/kaspersky/kesl/common/kesl.ini $TMPK/KESL/
			cp /var/opt/kaspersky/kesl/common/agreements.ini $TMPK/KESL/
		fi
		# KICS Nodes Linux
		if [ $(grep kics $TMPE/packages.txt | wc -l) -ne 0 ]; then
			mkdir $TMPK/KICS
			# KICS service status
			systemctl status kics > $TMPK/KICS/ctlstatus.txt
			systemctl cat kics > $TMPK/KICS/ctlcat.txt
			journalctl -xu "kics*" > $TMPK/KICS/journalkics.txt
			# copy events database
			cp /var/opt/kaspersky/kics/events.db $TMPK/KICS/
			cp /var/opt/kaspersky/kics/private\ storage/events.db $TMPK/KICS/
			cp /var/opt/kaspersky/kics/install-current/var/opt/kaspersky/kics/private/storage/events.db $TMPK/KICS/
			# general KICS application information
			/opt/kaspersky/kics/bin/kics-control --app-info > $TMPK/KICS/appinfo.txt
			# non-root permission checker
			echo "Dir check:" >> $TMPK/KICS/rootperm.txt
			ls -lLd / /var /var/opt /var/opt/kaspersky /opt /opt/kaspersky /opt/kaspersky/klnagent64 /opt/kaspersky/klnagent64/sbin /opt/kaspersky/klnagent64/sbin/klnagent /usr /usr/lib64 /usr/bin/kics-control | egrep -v '^.{5}-.{2}-.*root *root' >> $TMPK/KICS/kics.rootperm.txt
			echo "kics libs:" >> $TMPK/KICS/rootperm.txt
			for d in $(cat /proc/$(pidof -s kics)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KICS/rootperm.txt
			echo "kics-gui libs:" >> $TMPK/KICS/rootperm.txt
			for d in $(cat /proc/$(pidof -s kics-gui)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KICS/rootperm.txt
			echo "nagent libs:" >> $TMPK/KICS/rootperm.txt
			for d in $(cat /proc/$(pidof -s klnagent)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KICS/rootperm.txt
			echo "connection errors:" >> $TMPK/KICS/rootperm.txt
			(kics-control -E --query "EventType=='RemoteConnectionRejected'" | egrep "RemoteConnectionRejected|Reason|Path|Process" | sort --unique) >> $TMPK/KICS/rootperm.txt 2>&1
			echo "Process|Reason|Path" >> $TMPK/KICS/rootperm.txt
			sqlite3 $TMPK/KICS/events.db 'SELECT DISTINCT Process, Reason, Path FROM events WHERE EventType=134;' >> $TMPK/KICS/rootperm.txt
			# KICS license
			/opt/kaspersky/kics/bin/kics-control -L --query > $TMPK/KICS/license.txt
			# KICS settings export
			/opt/kaspersky/kics/bin/kics-control --export-settings > $TMPK/KICS/expset.txt
			/opt/kaspersky/kics/bin/kics-control --get-app-set > $TMPK/KICS/appset.txt
			/opt/kaspersky/kics/bin/kics-control --get-net-set > $TMPK/KICS/netset.txt
			# KICS task list
			/opt/kaspersky/kics/bin/kics-control --get-task-list > $TMPK/KICS/tasklist.txt
			# KICS task settings
			for i in $(kics-control --get-task-list | egrep '(ID|Идентификатор)' | awk '{print $3}'); do echo 'TaskID '$i $(kics-control --get-task-list | grep -w -B1 $i | grep Name | awk '{print $2}') 'configuration:' >> $TMPK/KICS/taskset$i.txt; kics-control --get-settings $i >> $TMPK/KICS/taskset$i.txt; printf '\n' >> $TMPK/KICS/taskset$i.txt; cat $TMPK/KICS/taskset$i.txt >> $TMPK/KICS/taskset.all.txt; done
			# KICS host Device list, App list
			/opt/kaspersky/kics/bin/kics-control --get-device-list > $TMPK/KICS/devlist.txt
			/opt/kaspersky/kics/bin/kics-control --get-app-list > $TMPK/KICS/applist.txt
			# KICS update log
			/opt/kaspersky/kics/bin/kics-control -E --query "TaskType == 'Update'" > $TMPK/KICS/updateLog.txt
			# get recursive listing of product directory
			ls -la /var/opt/kaspersky/kics > $TMPK/KICS/listing.txt
			find /var/opt/kaspersky/kics/ >> $TMPK/KICS/listing.txt
			# various configs of interest
			cp /var/opt/kaspersky/kics/private/exported_settings.ini $TMPK/KICS/
			cp /var/opt/kaspersky/kics/private/storage/appSettings.xml $TMPK/KICS/
			cp /var/opt/kaspersky/kics/common/kics.ini $TMPK/KICS/
			cp /var/opt/kaspersky/kics/common/agreements.ini $TMPK/KICS/
		fi
		# KESS Linux
		if [ $(grep kess $TMPE/packages.txt | wc -l) -ne 0 ]; then
			mkdir $TMPK/KESS
			# KESS service status
			systemctl status kess > $TMPK/KESS/ctlstatus.txt
			systemctl cat kess > $TMPK/KESS/ctlcat.txt
			journalctl -xu "kess*" > $TMPK/KESS/journalkess.txt
			# copy events database
			cp /var/opt/kaspersky/kess/events.db $TMPK/KESS/
			cp /var/opt/kaspersky/kess/private\ storage/events.db $TMPK/KESS/
			cp /var/opt/kaspersky/kess/install-current/var/opt/kaspersky/kess/private/storage/events.db $TMPK/KESS/
			# general KESS application information
			/opt/kaspersky/kess/bin/kess-control --app-info > $TMPK/KESS/appinfo.txt
			# non-root permission checker
			echo "Dir check:" >> $TMPK/KESS/rootperm.txt
			ls -lLd / /var /var/opt /var/opt/kaspersky /opt /opt/kaspersky /opt/kaspersky/klnagent64 /opt/kaspersky/klnagent64/sbin /opt/kaspersky/klnagent64/sbin/klnagent /usr /usr/lib64 /usr/bin/kess-control | egrep -v '^.{5}-.{2}-.*root *root' >> $TMPK/KESS/rootperm.txt
			echo "kess libs:" >> $TMPK/KESS/rootperm.txt
			for d in $(cat /proc/$(pidof -s kess)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KESS/rootperm.txt
			echo "kess-gui libs:" >> $TMPK/KESS/rootperm.txt
			for d in $(cat /proc/$(pidof -s kess-gui)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KESS/rootperm.txt
			echo "nagent libs:" >> $TMPK/KESS/rootperm.txt
			for d in $(cat /proc/$(pidof -s klnagent)/maps | awk '{print $6}' | grep ^/ | grep -v 'kaspersky' | sort | uniq); do ls -la $d | egrep -v '^-.{4}-.{2}-.*root root'; done >> $TMPK/KESS/rootperm.txt
			echo "connection errors:" >> $TMPK/KESS/rootperm.txt
			(kess-control -E --query "EventType=='RemoteConnectionRejected'" | egrep "RemoteConnectionRejected|Reason|Path|Process" | sort --unique) >> $TMPK/KESS/rootperm.txt 2>&1
			echo "Process|Reason|Path" >> $TMPK/KESS/rootperm.txt
			sqlite3 $TMPK/KESS/events.db 'SELECT DISTINCT Process, Reason, Path FROM events WHERE EventType=134;' >> $TMPK/KESS/rootperm.txt
			# KESS license
			/opt/kaspersky/kess/bin/kess-control -L --query > $TMPK/KESS/license.txt
			# KESS settings export
			/opt/kaspersky/kess/bin/kess-control --export-settings > $TMPK/KESS/expset.txt
			/opt/kaspersky/kess/bin/kess-control --get-app-set > $TMPK/KESS/appset.txt
			/opt/kaspersky/kess/bin/kess-control --get-net-set > $TMPK/KESS/netset.txt
			# KESS task list
			/opt/kaspersky/kess/bin/kess-control --get-task-list > $TMPK/KESS/tasklist.txt
			# KESS task settings
			for i in $(kess-control --get-task-list | egrep '(ID|Идентификатор)' | awk '{print $3}'); do echo 'TaskID '$i $(kess-control --get-task-list | grep -w -B1 $i | grep Name | awk '{print $2}') 'configuration:' >> $TMPK/KESS/taskset$i.txt; kess-control --get-settings $i >> $TMPK/KESS/taskset$i.txt; printf '\n' >> $TMPK/KESS/taskset$i.txt; cat $TMPK/KESS/taskset$i.txt >> $TMPK/KESS/taskset.all.txt; done
			# KESS host Device list, App list
			/opt/kaspersky/kess/bin/kess-control --get-device-list > $TMPK/KESS/devlist.txt
			/opt/kaspersky/kess/bin/kess-control --get-app-list > $TMPK/KESS/applist.txt
			# KESS update log
			/opt/kaspersky/kess/bin/kess-control -E --query "TaskType == 'Update'" > $TMPK/KESS/updateLog.txt
			# get recursive listing of product directory
			ls -la /var/opt/kaspersky/kess > $TMPK/KESS/listing.txt
			find /var/opt/kaspersky/kess/ >> $TMPK/KESS/listing.txt
			# various configs of interest
			cp /var/opt/kaspersky/kess/private/exported_settings.ini $TMPK/KESS/
			cp /var/opt/kaspersky/kess/private/storage/appSettings.xml $TMPK/KESS/
			cp /var/opt/kaspersky/kess/common/kess.ini $TMPK/KESS/
			cp /var/opt/kaspersky/kess/common/agreements.ini $TMPK/KESS/
		fi
		# LENA
		if [ $(grep epagent $TMPE/packages.txt | wc -l) -ne 0 ]; then
			mkdir $TMPK/LENA
			cp -R /var/opt/kaspersky/epagent $TMPK/LENA/var-epagent
			cp -R /etc/opt/kaspersky/epagent $TMPK/LENA/etc-epagent
			cp -R /var/log/audit $TMPK/LENA/auditlog
			cp -R /tmp/agentdumps $TMPK/LENA/agentdumps
			fuser /run/log/audit-messages | awk '{print $1,$2}' | xargs ps -p > $TMPK/LENA/messages-pids.txt
		fi
		#KPSN detection and response
		if [ $(grep kpsn $TMPE/packages.txt | wc -l) -ne 0 ]; then 
			# components status
			monit status > $TMPK/monit.txt
			runuser -l ksnuser -c 'monit status' >> $TMPK/monit.txt
			mkdir $TMPK/KPSN/
			mkdir $TMPK/KPSN/pubdata/
			mkdir $TMPK/KPSN/gateway/
			mkdir $TMPK/KPSN/etc/
			# KPSN listings
			ls -laR /usr/local/kpsn /usr/local/ksn > $TMPK/KPSN/lskpsn.txt
			# product logs
			#find /usr/local/ksn/log/ -type f -newermt $(date +%Y-%m-%d -d '-3 days') -printf "%f\n" -exec cp {} $TMPK/KPSN/ >/dev/null 2>&1 \;
			cp -R /usr/local/ksn/log/ $TMPK/KPSN
			# apache logs
			cp -R /var/log/apache/ $TMPL
			cp -R /var/log/httpd/ $TMPL
			# product configuration
			cp -R /usr/local/ksn/var/pubdata/ $TMPK/KPSN
			cp -R /usr/local/ksn/var/gateway/ $TMPK/KPSN
			cp -R /usr/local/ksn/etc/ $TMPK/KPSN
			# python packages
			pip list > $TMPK/KPSN/pip.txt
		fi
		# ScanEngine
			cp /etc/klScanEngineUI.xml $TMPK/scanengine.klScanEngineUI.xml
			cp /etc/kavhttpd.xml $TMPK/scanengine.kavhttpd.xml
			cp /etc/kavicapd.xml $TMPK/scanengine.kavicapd.xml
			cp /opt/kaspersky/ScanEngine/version $TMPK/scanengine.version
			cp /opt/kaspersky/ScanEngine/bin/bases/data/u1313g.xml $TMPK/scanengine.u1313g.xml
			sudo -u postgres pg_dump -f /tmp/kavbase.sql -d kavebase
			mv /tmp/kavbase.sql $TMPK/scanengine.kavbase.sql
		# KSC Linux Administration Server
		if [ $(grep ksc64 $TMPE/packages.txt | wc -l) -ne 0 ]; then
			mkdir $TMPK/KSC
			# KSC install logs
			cp /tmp/klregserver*.log $TMPK/KSC
			cp /tmp/klfoc*.log $TMPK/KSC
			cp /tmp/klnagent_srv*.log $TMPK/KSC
			cp /tmp/ksc64_install.log $TMPK/KSC
			# KSC server logs
			cp /tmp/\$klserver*.log $TMPK/KSC
			cp /tmp/\$klnagent*.log $TMPK/KSC
			cp /tmp/\$klactprx*.log $TMPK/KSC
			cp /tmp/\$klcsweb*.log $TMPK/KSC
			cp /tmp/\$up2date*.log $TMPK/KSC
			cp /tmp/\$kladduser*.log $TMPK/KSC
			cp /tmp/klnagchk*.log $TMPK/KSC
			# KSC kuu logs
			cp /opt/kaspersky/ksc64/kuu/report.txt $TMPK/KSC/kuu.report.txt
			cp /opt/kaspersky/ksc64/kuu/trace.log $TMPK/KSC/kuu.trace.log
			cp /opt/kaspersky/ksc64/kuu/updater.ini $TMPK/KSC/kuu.updater.ini
			# DB settings
			mkdir $TMPK/KSC/MariaDB
			cp /etc/mysql/my.cnf $TMPK/KSC/MariaDB/
			mkdir $TMPK/KSC/PostgreSQL
			cp /etc/postgresql/*/main/postgresql.conf $TMPK/KSC/PostgreSQL/
			journalctl -x -u "KSC*" -u "kl*" > $TMPK/KSC/journalKSC.txt
			journalctl -x -u "postgresql" -u "mariadb" -u "mysql" > $TMPK/KSC/journalDB.txt
			for i in $(systemctl list-units -t service --full -all --plain --no-legend | egrep '(^KSC|^kl|postgresql|mariadb|mysql)' | awk '{ print $1 }'); do systemctl status $i >> $TMPK/KSC/ctlstatus_$i.txt; done
		fi
		# KSC Linux Web Console
		if [ $(grep ksc-web-console $TMPE/packages.txt | wc -l) -ne 0 ]; then
			# Web console logs
			mkdir $TMPK/KSC-web-console
			cp -R /var/opt/kaspersky/ksc-web-console/logs/ $TMPK/KSC-web-console
			cp /etc/ksc-web-console-setup.json $TMPK/KSC-web-console
		fi
		# KUMA
		if [ $(grep kuma- $TMPE/systemctl.txt | wc -l) -ne 0 ]; then
			# KUMA satellites logs
			mkdir $TMPK/KUMA
			mkdir $TMPK/KUMA/clickhouse
			cp -R /opt/kaspersky/kuma/clickhouse/logs/ $TMPK/KUMA/clickhouse
			mkdir $TMPK/KUMA/grafana
			cp -R /opt/kaspersky/kuma/grafana/data/log/ $TMPK/KUMA/grafana
			mkdir $TMPK/KUMA/mongodb
			mkdir $TMPK/KUMA/mongodb/log
			cp /opt/kaspersky/kuma/mongodb/log/mongod.log $TMPK/KUMA/mongodb/log
			mkdir $TMPK/KUMA/journals
			journalctl -x -u "kuma*" > $TMPK/KUMA/journals/all.txt
			for i in $(systemctl list-units -t service --full --all --plain --no-legend | grep kuma- | awk '{ print $1 }'); do systemctl status $i >> $TMPK/KUMA/services.txt; done
			for i in $(systemctl list-units -t service --full --all --plain --no-legend | grep kuma- | awk '{ print $1 }'); do journalctl -x -u $i > $TMPK/KUMA/journals/$i.log; done	
			/opt/kaspersky/kuma/kuma version > $TMPK/KUMA/execvers.txt
			kumalogs="$(find /opt/kaspersky/kuma/core/log/core /opt/kaspersky/kuma/storage/*/log/storage /opt/kaspersky/kuma/collector/*/log/collector /opt/kaspersky/kuma/correlator/*/log/correlator -type f)"
			tar cfh $TMPK/KUMA/logs.tar $kumalogs
			# KUMA services and resources export
			/opt/kaspersky/kuma/mongodb/bin/mongo kuma --eval 'db.resources.find({"kind":"storage"}).forEach(printjson)' | sed '1,4d' > $TMPK/KUMA/resources.json
			/opt/kaspersky/kuma/mongodb/bin/mongo kuma --eval 'db.services.find({"kind":"storage"}).forEach(printjson)' | sed '1,4d' > $TMPK/KUMA/services.json
		fi
	elif [ "$SYSTEM_TYPE" = "FREEBSD" ]; then
	    # mounts
        mount > $TMPE/hdd.txt
        # free space
        df -h >> $TMPE/hdd.txt
        # free inodes
        df -hi >> $TMPE/hdd.txt
        # list of users
        cp /etc/passwd $TMPE/passwd
        # list of groups
        cp /etc/group $TMPE/group
        # status of linked files into kernel
        kldstat > $TMPE/kldstat.txt
        # inter-process communication status (active message queues, semaphore sets, shared memory segments)
        ipcs -a > $TMPE/ipcs.txt
        # proccess list
		top -d1 > $TMPE/top.txt
		# virtual memory statistics
        vmstat -a > $TMPE/vmstata.txt
        # forks
		vmstat -f > $TMPE/vmstatf.txt
		# interrupts
		vmstat -i > $TMPE/vmstati.txt
		# dynamic memory
		vmstat -m > $TMPE/vmstatm.txt
		# kernel state variables
		sysctl -a > $TMPE/sysctl.txt
		# proccess list
		ps axo comm,user,group,state,rss,vsz,pcpu,pmem,time,command >  $TMPE/ps.txt
		# user limits
        ulimit -a > $TMPE/ulimit.txt
        # list open files
		fstat > $TMPE/fstat.txt
		# sockets
		netstat -na > $TMPE/nestat.txt
		# routing table
		netstat -r > $TMPE/route.txt
		# IO statistics
		iostat -xc 3 > $TMPE/iostat.txt
		# packages list
		pkg_info > $TMPE/pkgi1.txt
		echo "N" | pkg info > $TMPE/pkgi2.txt
		# firewall state
		ipfw show  > $TMPE/ipfw.txt
		# time running from boot
        uptime > $TMPE/uptime.txt
        # hostname
        hostname > $TMPE/hostname.txt
        # hosts file
        cp /etc/hosts $TMPE
        # DNS configuration
        cp /etc/resolv.conf $TMPE
        # get network interfaces
        ifconfig > $TMPE/ifconfig.txt
        # periodic jobs
        cp -R /etc/periodic $TMPE
        cp /etc/crontab $TMPE
        # listing of core directories
	ls -la / /tmp /usr/local /var /etc  > $TMPE/lsroot.txt
	# recursive listing of product directories
	ls -laR /usr/local/kaspersky /var/db/kaspersky > $TMPE/lskasp.txt
        # current date
        date > $TMPE/date.txt
        # check if internet is available
        ping -c2 support.kaspersky.com > $TMPE/ping.txt
        # product configuration files
		cp -R /usr/local/etc/kaspersky/klms  $TMPK/etc
		cp /var/db/kaspersky/klms/postgresql/postgresql.conf $TMPK/
		# export of KLMS settings
		klms-control --export-settings -f $TMPK/klms8set.txt
		# export of KLMS rules
		klms-control --export-rules -f $TMPK/klms8rules.xml
		# KLMS license information
		klms-control -l --get-installed-keys > $TMPK/klms8.lic
		# KLMS detection statistics
		klms-control --dashboard --month > $TMPK/klms8.stats
		# sendmail utility information
        SENDMAIL=$(which sendmail)
        echo "$SENDMAIL" >> $TMPK/lms-sm
        ls -l "$SENDMAIL" >> $TMPK/lms-sm
		ls -l /usr/sbin/mailwrapper >> $TMPK/lms-sm
	fi

	echo "logs..." | tee -a $TMP/clog

	TMPL=$TMP/logs
	mkdir $TMPL
	
	# kernel ring buffer / system message buffer
	dmesg > $TMPL/dmesg.txt
	dmesg -T > $TMPL/dmesgt.txt
	ls -laR /var/log/ > $TMPL/log_list.txt

	if [ "$SYSTEM_TYPE" = "DARWIN" ]; then
	    # system logs
		tail -1000 /var/log/mail.log > $TMPL/mail.log.txt
		tail -3000 /var/log/system.log > $TMPL/system.log
		cp /var/log/install.log $TMPL/install.log
		# product logs
		cp /var/log/kav_daemon_stderr.log $TMPL/kav_daemon_stderr.log
		cp /var/log/kav_daemon_stdout.log $TMPL/kav_daemon_stdout.log
		cp /var/log/kav_sysextctrld_stderr.log $TMPL/kav_sysextctrld_stderr.log
		cp /var/log/kav_sysextctrld_stdout.log $TMPL/kav_sysextctrld_stdout.log
		# product traces
		mkdir $TMPL/mac_traces
		mkdir $TMPL/mac_traces/copy
        mkdir $TMPL/mac_traces/ucopy
        cp /Library/Logs/klnagent_trace.log $TMPL/klnagent_trace.log
        cp '/Library/Application Support/Kaspersky Lab/klnagent/Binaries/$klnagent-1103.log' $TMPL/klnagent-trace.log
		cp -R /Library/Logs/Kaspersky\ Lab/* $TMPL/mac_traces/copy
		cp -R ~/Library/Logs/Kaspersky\ Lab/* $TMPL/mac_traces/ucopy
		for pathname in /Users/*/Library/Logs/Kaspersky\ Lab/*; do
            ndir=$(echo $TMPL/mac_traces/fcopy/$( dirname -- "$pathname" ) |  sed 's/ /\ /g')
            mkdir -p "$ndir"
            cp -i -- "$pathname" "$ndir/$( basename -- "$pathname" )"
        done
        # crash reports
		cp -R /Library/Logs/DiagnosticReports/ $TMPL/DiagnosticReports/;
		cp -R ~/Library/Logs/DiagnosticReports/ $TMPL/DiagnosticReports/;
		# system logs
		log show --debug --predicate 'subsystem == "com.kaspersky.kav.sysext"'  --last 10m --info > $TMPL/logShowKavSysExt.txt
		log show --debug --last 30m --info > $TMPL/logShow30min.txt


	elif [ "$SYSTEM_TYPE" = "LINUX" ]; then
		# system logs
		tail -10000 /var/log/maillog > $TMPL/maillog.txt
		tail -10000 /var/log/mail.log > $TMPL/mail.log.txt
		tail -10000 /var/log/mail.err > $TMPL/mail.err.txt
		tail -10000 /var/log/mail.warn > $TMPL/mail.warn.txt
		tail -10000 /var/log/syslog > $TMPL/syslog.txt
		tail -10000 /var/log/boot.log > $TMPL/bootlog.txt
		tail -10000 /var/log/kern.log > $TMPL/kernlog.txt
		tail -n10 /var/log/upstart/*.log > $TMPL/upstartlog.txt
		tail -10000 /var/log/messages > $TMPL/messages.txt
		tail -10000 /var/log/dmesg > $TMPL/dmesg.log.txt
		tail -10000 /var/log/audit/audit.log > $TMPL/audit.log.txt
		# product logs
		cp -R /var/log/kaspersky/ $TMPL
		# system logs
		journalctl -n 10000 > $TMPL/journal.txt
		journalctl -p 4 -n 10000 > $TMPL/journal.4.txt
		journalctl -o verbose -p 4 -n 100 > $TMPL/journal.v.4.txt
		# KESL/KICS/KESS crash dumps
		#gathering dependencies
		get_deps()
		{
			ldd "$1" 2>/dev/null | grep '=>' | grep -v 'kaspersky' | awk '{print $3}' | grep '^/' | grep "$2"
		}
		#gathering additional dependant libraries
		collect_dumps()
		{
			dst_dir="$1"
			product="$2"
			exe="/opt/kaspersky/${product}/libexec/${product}"
			version="$(readlink /var/opt/kaspersky/${product}/install-current | grep -o ^.*_ | sed s/_//)"

			arch='unknown'
			case "$(file ${exe})" in
				*aarch64*) arch='arm64' ;;
				*x86-64*)  arch='64' ;;
				*32-bit*)  arch='32' ;;
			esac

			libcontainers="$(find /opt/kaspersky/${product}/lib${arch}/ -name libcontainers.so)"
			libinstrumental_services="$(find /opt/kaspersky/${product}/lib${arch}/ -name libinstrumental_services.so)"

			libs="$(get_deps ${exe})"
			libz="$(get_deps $libcontainers libz)"
			libresolv="$(get_deps $libinstrumental_services libresolv)"

			interp="$(ldd ${exe} | grep -Ev 'vdso|=>' | awk '{print $1}')"

			cache="$(ls /var/opt/kaspersky/${product}/common/updates/cache/* 2> /dev/null)"
			#dumps="$(ls /var/opt/kaspersky/${product}/common/dumps*/* 2>/dev/null)"
			#probably also intended to gather gui dumps, but ls does not work with subdirs, use find instead
			dumps="$(find /var/opt/kaspersky/${product}/common/dumps* -type f 2> /dev/null)"
			#klnagent="$(ls /opt/kaspersky/klnagent*/sbin/* 2>/dev/null)"

			#archiving collected data
			tar cfh "${dst_dir}/${product}_${version}_${arch}.tar" $libs $libz $libresolv $interp $cache $dumps $klnagent
		}
		# checking if there are some dumps
		for product in kesl kics kess; do
			if [ $(find /var/opt/kaspersky/${product}/common/dumps* -type f 2> /dev/null | wc -l) -gt 0 ]; then
				#dumps found, gathering extra information
				mkdir -p $TMP/libs_and_dumps
				collect_dumps "$TMP/libs_and_dumps" "${product}"
			fi
		done
		
	elif [ "$SYSTEM_TYPE" = "FREEBSD" ]; then
	    # system logs
		tail -1000 /var/log/maillog > $TMPL/maillog.txt
		tail -1000 /var/log/messages > $TMPL/messages.txt
		dmesg > $TMPL/dmesg.txt
		# product logs
		cp -R /var/log/kaspersky/ $TMPL
	fi

	if [ -d "$TMP" ]; then
		echo -n "$TMP unpacked size: " | tee -a $TMP/clog
		du -sh "$TMP" | awk '{print $1}'| tee -a $TMP/clog
	fi

	echo -n "packing... " | tee -a $TMP/clog
	tar czf "$TMP/../$HOST_NAME-collect.tar.gz" $TMP

	report_result="$?"
	if [ -f "$TMP/../$HOST_NAME-collect.tar.gz" ]; then
		echo -n "packed size: "
		du -sh "$TMP/../$HOST_NAME-collect.tar.gz" | awk '{print $1}'
	fi

	echo -n "free space post-check:"
	df -h $TMP | tail -n 1 | awk '{print " "$4" available in "$6" mount point"}'

	echo "cleaning..."
	rm -rf $TMP

	if [ $report_result -eq 0 ]; then
		echo "All done!"
	else
		echo "packing finished with error $report_result. No space left on device?"
	fi

	exec 2>&6 6>&-

fi

exit $ERROR

