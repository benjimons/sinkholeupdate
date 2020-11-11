# sinkholeupdate
This script faciliates the addition and deletion of a domain to the local DNS server that zone transfers into a remote DNS server

https://dnsrpz.info/

What is RPZ
Domain Name Service Response Policy Zones (DNS RPZ) is a method that allows a nameserver administrator to overlay custom information on top of the global DNS to provide alternate responses to queries. It is currently implemented in the ISC BIND nameserver (9.8 or later). Another generic name for the DNS RPZ functionality is "DNS firewall".

# Requirements 
Python 2.x and dnspython (http://www.dnspython.org)
Bind 9.8 or later
alexa.dat file (Plain text file of rows of domains to whitelist/force halt if attempted to be added)

# Usage
```
Usage:  ./sinkhole.py -z <all|whitelist|phishing|malware> [[-a|-r]<-d <domain>|-f <inputfile>>]|-l|-s <searchtring>|-F
        -z <rpz name> the zone name to use (all|whitelist|phishing|malware)
        -a [-d <domain>|-f <input file>] add domain(s) to zone file - existing domains will be overwritten
        -r [-d <domain>|-f <input file>] remove domain(s) from zone file
        -l list all domains in given zone
        -s <string> search for domain in given zone
        -F <string> force addition if domain trying to be added is in whitelist file
        -S <string> subdomain for sinkhole (default is -z parameter)
Examples:
Add domain to the malware zonefile using default sink
        ./sinkhole.py -z malware -ad thisbaddomain.com
Add domain to the phishing zonefile using another sink
        ./sinkhole.py -z phishing -ad imabaddomain.com -S phishing3
Remove a domain from the phishing zonefile
        ./sinkhole.py -z phishing -rd domaintoremove.co.nz
Search for string softpedia in the malware zonefile
        ./sinkhole.py -z malware -s softpedia.com
List all domains in the phishing zonefile
        ./sinkhole.py -lz phishing
```
