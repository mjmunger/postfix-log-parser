#!/usr/bin/env python
import os,sys,re,hashlib,json

class logRejection:
	rawLine            = None
	remoteServer       = None
	ipAddress          = None
	disposition        = None
	recipient          = None
	sender             = None
	fromDomain         = None
	fromTLD            = None
	hash               = None
	timestamp          = None
	queue              = None
	action             = None
	valid              = False
	debug              = False
	stopOnParseFailure = False

	def __init__(self,line,debug,stopOnParseFailure):
		self.stopOnParseFailure = stopOnParseFailure
		self.debug              = debug
		self.rawLine            = line

		if not self.isDisposition():
			return None

		self.valid = True

		self.parseTimestamp()
		self.parseRecipient(line)
		self.parseSender(line)
		self.parseFromDomain()
		self.parseRemoteServer()
		self.hashLine()

	def isDisposition(self):
		regex = "([A-Z0-9]{5,11}): ([a-z]+):(.*;)"
	 	p = re.compile(regex)
	 	r = p.search(self.rawLine)
	 	if not r:
	 		return False

	 	self.queue       = r.group(1)
	 	self.action      = r.group(2)
	 	buf              = r.group(3).split(':')
	 	buf.pop(0)
	 	self.disposition = ":".join(buf).strip()

	 	if self.debug:
	 		print ""
	 		print "".ljust(80,'=')
	 		print self.rawLine.strip()
	 		print "".ljust(80,'-')
	 		print "Queue".ljust(18),
	 		print self.queue
	 		print "Action".ljust(18),
	 		print self.action
	 		print "Disposition".ljust(18),
	 		print self.disposition

	 	return True
		

	# def parseRemoteAndDispotision(self,line):
	# 	regexMessage = r"RCPT from ([a-zA-Z\.0-9-]*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]): ([a-zA-Z0-9@ \.\<\>:/\?=-]*)"
	# 	p = re.compile(regexMessage)
	# 	r = p.search(line)
	# 	if(r):
	# 		self.remoteServer = r.group(1)
	# 		self.ipAddress    = r.group(2)
	# 		self.disposition  = r.group(3)

	def parseRecipient(self,line):
		regexMessage = r"to=\<([a-zA-Z0-9@\._=\+&/|\?-]*)\>"
		p = re.compile(regexMessage)
		r = p.search(line)
		if not r:
			if self.debug:
				print "Cannot parse recipient for: ",
				print line
			if self.stopOnParseFailure:
				sys.exit('Stopped on parse failure as you requested.')
			return False
		self.recipient = r.group(1)

		if self.debug:
			print "To:".ljust(18),
	 		print self.recipient

	def parseSender(self,line):
		regexMessage = r"from=\<([a-zA-Z0-9@\._=\+&/|\?-]*)\>"
		p = re.compile(regexMessage)
		r = p.search(line)
		if not r:
			if self.debug:
				print "Cannot parse sender for: ",
				print line
			if self.stopOnParseFailure:
				sys.exit('Stopped on parse failure as you requested.')
			return False
		self.sender = r.group(1)

		if self.debug:
			print "From:".ljust(18),
	 		print self.sender

	def parseFromDomain(self):
		if not self.sender:
			return False

		buf = self.sender.split('@')
		if(len(buf) > 1):
			self.fromDomain = buf[1]
		else:
			self.fromDomain = ''

		buf = self.sender.split('.')
		if(len(buf) > 1):
			self.fromTLD = buf[len(buf)-1]
		else:
			self.fromTLD = ''

		if self.debug:
			print "From Domain:".ljust(18),
	 		print self.fromDomain
			print "From TLD:".ljust(18),
	 		print self.fromTLD

	def hashLine(self):
		m = hashlib.sha256()
		m.update(self.rawLine)
		self.hash = m.hexdigest()

	def parseTimestamp(self):
		regexMessage = r"(^[a-zA-Z]{3} {1,3}[\d]{1,2} [\d]{1,2}:[\d]{1,2}:[\d]{1,2})"
		p = re.compile(regexMessage)
		r = p.search(line)
		if not r:
			if self.debug:
				print "Cannot parse timestamp for: ",
				print line
			if self.stopOnParseFailure:
				sys.exit('Stopped on parse failure as you requested.')

		self.timestamp = r.group(1)

		if self.debug:
			print "Timestamp".ljust(18),
			print self.timestamp

	def parseRemoteServer(self):
		regexMessage = r"RCPT from ([a-zA-Z\.0-9-]*)\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"
		p = re.compile(regexMessage)
		r = p.search(line)
		if not r:
			if self.debug:
				print "Cannot parse remote server for: ",
				print line
			if self.stopOnParseFailure:
				sys.exit('Stopped on parse failure as you requested.')
			return False

		self.remoteServer = r.group(1)
		self.ipAddress = r.group(2)

		if self.debug:
			print "Remote Server:".ljust(18),
			print self.remoteServer
			print "Remote IP Address".ljust(18),
			print self.ipAddress


if "-h" in sys.argv:
	print "POSTFIX LOG SCANNER"
	print ""
	print "SUMMARY:"
	print ""
	print "This script reads /var/log/mail.log and parses lines that include a"
	print "disposition for an email (rejections) and saves that information in a json"
	print "file, which can then be parsed and imported into a database."
	print ""
	print "USAGE:"
	print "./scan-postfix-log.py [options]"
	print ""
	print " -d         Debug Mode. Prints out information about lines it parsed and what it found."
	print " -f [path]  Specify a log file to parse. Default: /var/log/mail.log"
	print " -h         Displays this help file."
	print " -s         Stop on parse failure. If any line cannot be parsed, stop processing."
	print ""
	
	sys.exit()

debug              = True if '-d' in sys.argv else False
logfile            = '/var/log/mail.log' if not '-f' in sys.argv else sys.argv[sys.argv.index('-f')+1]
stopOnParseFailure = True if '-s' in sys.argv else False

logdata = []
with open(logfile) as f:
	for line in f:
		thisLine = logRejection(line,debug,stopOnParseFailure)
		if not thisLine.valid:
			continue

		entry = {}
		entry['hash']           = thisLine.hash
		entry['timestamp']      = thisLine.timestamp
	  	entry['from']           = thisLine.sender
		entry['to']             = thisLine.recipient
		entry['remoteServer']   = thisLine.remoteServer
		entry['remoteIP']       = thisLine.ipAddress
		entry['fromDomain']     = thisLine.fromDomain
		entry['fromTLD']        = thisLine.fromTLD
		entry['disposition']    = thisLine.disposition
		entry['action']         = thisLine.action
		logdata.append(entry)
			
with open('/tmp/rejection.json', 'w') as outfile:
    json.dump(logdata, outfile)