pentest-machine
------
Automates some pentesting work via an nmap XML file. As soon as each command finishes it writes its output to the terminal and the files in output-by-service/ and output-by-host/. Runs fast-returning commands first. Please send me protocols/commands/options that you would like to see included.

* HTTP
  * whatweb
    * WPScan (only if whatweb returns a WordPress result)
  * EyeWitness with active login attempts
  * light dirb directory bruteforce
* DNS
  * nmap NSE dns-zone-transfer and dns-recursion
* MySQL
  * light patator bruteforce
* PostgreSQL
  * light patator bruteforce
* MSSQL
  * light patator bruteforce
* SMTP
  * nmap NSE smtp-enum-users and smtp-open-relay
* SNMP
  * light patador bruteforce
    * snmpcheck (if patador successfully finds a string)
* SMB
  * enum4linux -a
  * nmap NSE smb-enum-shares, smb-vuln-ms08-067, smb-vuln-ms17-010
* SIP
  * nmap NSE sip-enum-users and sip-methods
  * svmap
* RPC
  * showmount -e
* NTP
  * nmap NSE ntp-monlist
* FTP
  * light patator bruteforce
* Telnet
  * light patator bruteforce
* SSH
  * light patator bruteforce
* Wordpress 4.7
  * XSS content uploading
* To add:
* IPMI hash disclosure
* ike-scan (can't run ike-scans in parallel)



#### Installation
```
./setup.sh
source pm/bin/activate
```

#### Usage
Read from Nmap XML file

```sudo ./pentest-machine -x nmapfile.xml```


Perform an Nmap scan with a hostlist then use those results
The Nmap scan will do the top 1000 TCP ports and the top 100 UDP ports along with service enumeration
It will save as pm-nmap.[xml/nmap/gnmap] in the current working directory

```sudo ./pentest-machine -l hostlist.txt```


Skip the patator bruteforcing and all SIP and HTTP commands
-s parameter can skip both command names as well as protocol names

```sudo ./pentest-machine -s patator,sip,http -x nmapfile.xml```
