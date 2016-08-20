#!/usr/bin/python
#DNS Sinkhole maintenance script for addition, deletion and viewing of domains in rpz files.
#Last Updated: 26-11-2014
#Author: Ben McDowall 
#Requirements: Python 2.x and dnspython (http://www.dnspython.org)
#
#See usage for help on arguments
#

__author__ = 'Ben McDowall'
import os, sys, shutil, time, logging, getpass, getopt, dns.zone
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

#Config Vars
mailfrom = "example@example.com"
mailto = "example@example.com"
zonelist = ["malware", "phishing", "whitelist"] #name of rpz's you have
whitelist = "alexa-top-5000.dat" #This is the location of another file to reference before adding the domain to the bad lists.
globalttl = 3600 #This is the TTL of any records added/updated
globalsink = ".example.com" #what to append to the dns record we are overriding with
logfile = "logger.log"

#Set up the logger
user = getpass.getuser()
logger = logging.getLogger('dnssinkhole')
hdlr = logging.FileHandler(logfile)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s '+user+' %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

#Functions
def openzone ( rpz ):
	#Create the myzone zone object
	rpz=rpz+"-rpz."
	zone_file = "/etc/named/%sdb" % (rpz)
	try:
		with open(zone_file): pass
	except IOError, e:
		print ('The file %s doesnt exist!') %(rpz)
		logger.error(str(e))
		sys.exit(2)

	try:
		logger.debug("Getting zone object: "+rpz)
		myzone = dns.zone.from_file(zone_file, rpz)
		return myzone

        except DNSException, e:
		print e.__class__, e
		logger.error(str(e))
		sys.exit(2)
			

def savezone ( rpz, myzone ):
	rpz=rpz+"-rpz."

	try:
		localtime   = time.localtime()
		timestring  = time.strftime("%Y%m%d%H%M%S", localtime)
		logger.debug("Creating backup of /etc/named/"+rpz+"db as backups/"+rpz+"db"+timestring)
		shutil.copyfile("/etc/named/"+rpz+"db", "/opt/sinkhole/backups/"+rpz+"db"+timestring)
		
		for (name, ttl, rdata) in myzone.iterate_rdatas(SOA):
			serial = rdata.serial
			new_serial = serial + 1
			#print "Changing SOA serial from %d to %d" %(serial, new_serial)
			rdata.serial = new_serial

		#Commit the changes by writing the file
        	new_zone_file = "/etc/named/%sdb" % rpz
		logger.debug("Freezing zone: rndc freeze "+rpz)
		os.system("rndc freeze "+rpz)

	        logger.info("Writing modified zone to file "+new_zone_file)
	        myzone.to_file(new_zone_file, sorted=True)

		logger.debug("Reloading zone file: rndc reload "+rpz)
		os.system("rndc reload "+rpz)		

		logger.debug("Thawing zone: rndc thaw "+rpz)
		os.system("rndc thaw "+rpz)		
	

	except DNSException, e:
		logger.error(str(e))
		print e.__class__, e	

def checkwhitelists(domaintocheck):
	if domaintocheck in open(whitelist).read():
		sys.stdout.write("WARNING: "+domaintocheck+" This domain is in the Alexa top 1Million list")
		if force:
			sys.stdout.write(" FORCED ADDITION\n")
			logger.info("Domain forced addition: "+domaintocheck)
			return "ok"
		else:
			sys.stdout.write(" use -F option to force this add\n")
			logger.warning("Domain "+domaintocheck+" skipped, its in the whitelist list file("+whitelist+")")
			return "warning"
	else:
		return "ok"

def isvaliddomain(domaintocheck):
	if len(domaintocheck) > 255:
		logger.error("Domain is invalid: "+domaintocheck)
		print("Error domain %s is invalid!") %(domaintocheck)
		return "warning"
	if domaintocheck[-1:] == ".":
		domaintocheck = domaintocheck[:-1] # strip exactly one dot from the right, if present
	allowed = re.compile("((\*)|(?!-)[A-Z\d-]{1,63}(?<!-))$", re.IGNORECASE)
	validdomains = all(allowed.match(x) for x in domaintocheck.split("."))
	if validdomains:
		logger.debug("Domain valid: "+domaintocheck)
		return "ok"
	else:
		logger.error("Domain is invalid: "+domaintocheck)
		print("ERROR domain %s is invalid!") %(domaintocheck)
		return "warning"

def addblock( domain, myzone,  sink ):
	targetdomain=sink
	if checkwhitelists(domain)=="ok" and isvaliddomain(domain)=="ok":
		try:

		        #Create the name objects
	        	baddomain = dns.name.from_text(domain,None)
		        target = dns.name.from_text(targetdomain,None)

			#Look for any other entrys for domain and remove them		
			deleteblock(domain, myzone)

		        #Create the CNAME entry in the file
			rdataset = myzone.find_rdataset(baddomain, rdtype=CNAME, create=True)
		        rdata = dns.rdtypes.ANY.CNAME.CNAME(IN, CNAME, target)
		        print "Adding redirect for %s of type CNAME redirecting to %s" %(domain, targetdomain)
		        logger.info("Adding redirect for "+domain+" of type CNAME redirecting to "+targetdomain+" ttl:"+str(globalttl))
		        rdataset.add(rdata, ttl=globalttl)
		        logger.debug(rdataset.to_text())
			sendmail(domain, myzone)

			return 1

		except DNSException, e:
			print e.__class__, e
			logger.error(str(e))
			return 0
	

def deleteblock( domain, myzone ):
	try:

		#Find the domain in the dataset and delete it	
		print "Deleting domain", domain
	        logger.info("Deleting CNAME records for domain "+domain)
		myzone.delete_rdataset(domain, rdtype=CNAME)	
		return 1
	except DNSException, e:
		logger.error(str(e))
		print e.__class__, e

def searchdomain( domain, rpz ):
	rpz=rpz+"-rpz"
	logger.debug("Search for "+domain+" in "+rpz)

        zone_file = "/etc/named/%s.db" % rpz

	try:
		zone = dns.zone.from_file(zone_file, rpz)
		print "Zone origin:", zone.origin
		print("Domain Name,TTL,Target")

		for thisname, node in zone.nodes.items():        
			rdatasets = node.rdatasets
	                thisdomain=thisname.to_text()
			# If we found a partial match then print out the record
			if domain in thisdomain:
				for rdataset in rdatasets:
					for rdata in rdataset:
						if rdataset.rdtype == CNAME:
							sys.stdout.write(thisdomain+","+str(rdataset.ttl)+",")
							sys.stdout.write(str(rdata.target)+"\n")
	except DNSException, e:
		logger.error(str(e))
		print e.__class__, e

def sendmail(domain, rpz):
	sendmail_location = "/usr/sbin/sendmail" # sendmail location
	p = os.popen("%s -t" % sendmail_location, "w")
	p.write("From: %s\n" % mailfrom)
	p.write("To: %s\n" % mailto)
	p.write("Subject: New domain sinkholed\n")
	p.write("\n") # blank line separating headers from body
	p.write("New domain sinkholed: %s" % domain)
	status = p.close()
	print "Sent mail "+mailto+" to notify of this change"

#Main Routine

#Var initialaztion
add=False
remove=False 
search=False
listimport=False
search=False
list=False
force=False
domain=""
rpz=""
sink=""
domaincount=0



###############################
# o == option
# a == argument passed to the o
###############################
# Cache an error with try..except 
# Note: options is the string of option letters that the script wants to recognize, with 
# options that require an argument followed by a colon (':') i.e. -i fileName
#
try:
    myopts, args = getopt.getopt(sys.argv[1:],"f:z:d:s:armlFS:")
except getopt.GetoptError as e:
    print (str(e))
    print("Usage:  ./sinkhole.py -z <all|whitelist|phishing|malware> [[-a|-r]<-d <domain>|-f <inputfile>>]|-l|-s <searchtring>|-F")
    print("\t-z <rpz name> the zone name to use (all|whitelist|phishing|malware)")
    print("\t-a [-d <domain>|-f <input file>] add domain(s) to zone file - existing domains will be overwritten")
    print("\t-r [-d <domain>|-f <input file>] remove domain(s) from zone file")
    print("\t-l list all domains in given zone")
    print("\t-s <string> search for domain in given zone")
    print("\t-F <string> force addition if domain trying to be added is in whitelist file")
    print("\t-S <string> subdomain for sinkhole (default is -z parameter)")
    print("Examples:")
    print("Add domain to the malware zonefile using default sink\n\t./sinkhole.py -z malware -ad thisbaddomain.com")
    print("Add domain to the phishing zonefile using another sink\n\t./sinkhole.py -z phishing -ad imabaddomain.com -S phishing3")
    print("Remove a domain from the phishing zonefile\n\t./sinkhole.py -z phishing -rd domaintoremove.co.nz")
    print("Search for string softpedia in the malware zonefile\n\t./sinkhole.py -z malware -s softpedia.com")
    print("List all domains in the phishing zonefile\n\t./sinkhole.py -lz phishing")
    logger.error("Couldn't Run "+str(e))
    sys.exit(2)

#Determine the switches being used 
for o, a in myopts:
    if o == '-z':
        rpz=a
    elif o == '-d':
        domain=a
    elif o == '-f':
	listimport=True
        inputfile=a
    elif o == '-a':
	add=True
    elif o == '-r':
	remove=True	
    elif o == '-s':
	domain=a
	search=True	
    elif o == '-l':
	list=True	
    elif o == '-F':
	force=True	
    elif o == '-S':
	sink=a

if sink=="":
	sink=rpz+globalsink
else:
	sink=sink+globalsink

#Action on the switches
if search:
	if rpz=="":
		rpz="all"

	if rpz=="all":
		for s in zonelist:
			searchdomain(domain, s)
	else:
		searchdomain(domain, rpz)
elif list:
	if rpz=="":
		rpz="all"

	if rpz=="all":
		for s in zonelist:
			searchdomain("", s)
	else:
		searchdomain("", rpz)
elif listimport:
	domaincount=0

	if rpz=="all":
		print("You can modify one rpz per file")
		sys.exit()
	elif rpz=="":
		print("You must specify an rpz")
		sys.exit()
	else:
		
		try:
			with open(inputfile): pass
		except IOError, e:
			print ('The file %s doesnt exist!') %(inputfile)
			logger.error(str(e))
			sys.exit(2)

		thiszone = openzone( rpz )
	
		with open(inputfile, 'rU') as f:
			for line in f:
				thisdomain = line.strip()
				if add:
					if addblock( thisdomain, thiszone, sink ) == 1:
						domaincount+=1
				if remove:
					if deleteblock( thisdomain, thiszone ) == 1:
						domaincount+=1

		savezone(rpz, thiszone)

		print (" %s domains to the %s rpz") %(domaincount,rpz)
elif add:
	if rpz=="":
		print("You must specify an rpz eg -z malware")
		sys.exit()
	elif rpz=="all":
		print("You can only add to one rpz at one time")
		sys.exit()
	elif domain=="":
		print("You must specify a domain eg -d exampledomain.com")
		sys.exit()
	else:
		thiszone = openzone( rpz )
		if addblock( domain, thiszone, sink ) == 1:
			savezone( rpz, thiszone )
elif remove:
	if rpz=="":
		print("You must specify an rpz eg -z malware")
		sys.exit()
	elif rpz=="all":
		print("You can only remove from one rpz at one time")
		sys.exit()
	elif domain=="":
		print("You must specify a domain eg -d exampledomain.com")
		sys.exit()
	else:
		thiszone = openzone( rpz )
		deleteblock(domain, thiszone)
		savezone( rpz, thiszone )

