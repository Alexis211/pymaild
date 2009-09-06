#!/usr/bin/env python
import socket, sys, os, threading, base64, hashlib, time
import cfgfile

conf = cfgfile.cfgset()
conf.load("pymaild.conf",
		{"serverhost": ("What hosts to listen for", "127.0.0.1"),
			"smtpserverport": ("What port for the SMTP server", 25),
			"pop3serverport": ("What port for the POP3 server", 110),
			"serverhostname": ("Server's host name", "smtp.example.com"),
			"localdomain": ("Domain for which mail has to be kept", 'example.com'),
			"requireauth": ("Is authentication required for using the SMTP service ?", 1),
			"noauthhosts": ("Hosts which do not require authentication for using the SMTP service.", ['localhost']),
			"smtpmaxmailsize": ("Maximum mail size, in bytes", 10000000),
			"datapath": ("The path where mail and account list is stored", "/opt/pymaild/mail"),
			"usesmtprelay": ("Use a SMTP relay server for mail ?", 0),
			"smtprelay": ("Relay for mail. Will be used if usesmtprelay = 1 or if mail can't be delivered normally.", ""),
			"loglevel": ("Log level : 0 = no log, 1 = errors, 2 = more stuff, 3 = debug", 2),
			})

def log(level, message):
	if level <= conf.loglevel:
		logfile = open(conf.datapath + "/log", "a")
		l = ['System', 'Error', 'Information', 'Debug'][level]
		logfile.write('%i %s : %s\n' % (int(time.time()), l, message))
		logfile.close()

def sockReadLine(aconnection):
	line = ""
	while 1:
		a = aconnection.recv(1)
		if a == "\n":
			break
		elif a == "":
			aconnection.close()
			return ""
		else:
			line += a
	while line[-1:] == "\r" or line[-1:] == "\n":
		line = line[:-1]
	return line

def authenticate(username, password):
	fl = "%s:%s\n" % (username, password.lower())
	with open(conf.datapath + "/users", "r") as userlist:
		for line in userlist:
			if line == fl:
				userlist.close()
				return 1
	userlist.close()
	return 0

def isValidAddress(emailaddr):
	a = emailaddr.split('@')
	if len(a) != 2:
		return 0
	a = a[1].split('.')
	if len(a) == 1:
		return 0
	if len(a[-1]) not in range(2, 5): 
		return 0
	return 1

def reverseDNS(ipaddr):
	if ipaddr == "127.0.0.1":
		return "localhost"
	a = os.popen("host " + ipaddr)
	b = a.readline()
	a.close()
	r = b.split(' ')[-1][:-2]
	if r[-8:] == "NXDOMAIN":
		return "UNKNOWN"
	return r

def resolvDNS(hostname):
	if hostname == "localhost":
		return "127.0.0.1"
	a = os.popen("host " + hostname)
	b = a.readline()
	a.close()
	r = b.split(' ')[-1][:-1]
	if r[-10:] == "(NXDOMAIN)":
		return "0.0.0.0"
	return r

def mxServer(domain):
	if domain in mxServers:
		return mxServers[domain]
	a = os.popen("dig %s MX" % (domain))
	b = a.readlines()
	a.close()
	mxServers[domain] = []
	for l in b:
		if l != "\n" and l[0] != ';':
			t = l.split('\t')[-1]
			h = t.split(' ')[-1][:-2]
			mxServers[domain].append((h, resolvDNS(h), int(t.split(' ')[-2])))
	if len(mxServers[domain]) == 0:
		mxServers[domain] = [(conf.smtprelay, resolvDNS(conf.smtprelay), 99)]
	return mxServers[domain]

def getHead(filename):
	file = open(filename, "r")
	head = ""
	while 1:
		l = file.readline()
		head += l
		if l == ".\n" or l == ".\r\n":
			break
		if len(l) < 5:
			head += ".\r\n"
			break
	file.close()
	return head

def queueMail(sender, recipients, contents, senderinfo):
	mailid = hashlib.md5(sender + "#".join(recipients) + contents + str(time.time())).hexdigest().upper()
	mailid = mailid[:13] + '.' + mailid[13:-13] + '.' + mailid[-13:]
	file = open(conf.datapath + "/queued-" + mailid, "w")
	file.write("Received: from %s (%s [%s])\r\n" % senderinfo)
	file.write("\tby %s (SMTP Server) with SMTP id %s\r\n" % (conf.serverhostname, mailid))
	file.write(contents)
	file.close()
	th = QueueProcessThread(mailid, sender, recipients)
	th.start()
	return mailid

def sendErrorMail(error, data):
	if error == "cannot deliver":
		subject = "Mail cannot be delivered"
		recipients = [data[0]]
		message = "Hello\r\n\r\nSorry, your mail could not be delivered.\r\n"
		for l in data[2].split('\n'):
			if l[:8] == "Subject:":
				message += l
				break
		message += "\r\nRecipients: " + ",".join(data[1])
	elif error == "no such recipient":
		subject = "Mail sent to non-existent recipient"
		recipients = [data[0]]
		message = "Hello\r\n\r\nSorry, you sent a mail to a non-existent recipient, %s\r\n" % (data[1])
		for l in data[2].split('\n'):
			if l[:8] == "Subject:":
				message += l
				break
	else:
		return
	r = {}
	for a in recipients:
		s = a.split('@')
		if s[1] in r:
			r[s[1]].append(s[0])
		else:
			r[s[1]] = [s[0]]
	queueMail("daemon@" + conf.localdomain, r,
			"From: Mail Delivery Daemon <no-reply@%s>\r\nSubject: %s\r\n\r\n%s" 
			% (conf.localdomain, subject, message),
			('Mail Daemon', 'localhost', '127.0.0.1'))


def smtpSendMail(smtp_server, sender, recipients, contents_file):
	csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		csock.connect((smtp_server, 25))
	except socket.error:
		return 0
	if sockReadLine(csock)[:4] != "220 ":
		csock.close()
		return 0
	csock.send("ehlo %s\r\n" % (conf.serverhostname))
	log(3, "ehlo %s" % (conf.serverhostname))
	l = "...."
	while l[3] != ' ':
		l = sockReadLine(csock)
	if l[:4] != "250 ":
		csock.close()
		return 0
	csock.send("mail from: <%s>\r\n" % (sender))
	log(3, "mail from: <%s>" % (sender))
	if sockReadLine(csock)[:4] != "250 ":
		csock.close()
		return 0
	for r in recipients:
		csock.send("rcpt to: <%s>\r\n" % (r))
		log(3, "rcpt to: <%s>" % (r))
		if sockReadLine(csock)[:4] != "250 ":
			csock.close()
			return 0
	csock.send("data\r\n")
	log(3, "data")
	if sockReadLine(csock)[:4] != "354 ":
		csock.close()
		return 0
	file = open(contents_file, "r")
	while 1:
		l = file.readline()
		csock.send(l)
		if l == ".\r\n" or l == ".\n":
			break
		if l == "":
			csock.send("\r\n.\r\n")
			break
	file.close()
	if sockReadLine(csock)[:4] != "250 ":
		csock.close()
		return 0
	csock.send("quit\r\n")
	log(3, "quit")
	csock.close()
	return 1

def deliverLocalMail(sender, recipients, contents_file, mailid):
	for r in recipients:
		if os.path.isdir(conf.datapath + "/" + r):
			uid = hashlib.md5(sender + mailid + r + str(time.time())).hexdigest()
			file = open(conf.datapath + "/" + r + "/mail", "a")
			file.write(uid + "\n")
			file.close()
			os.system("cp %s %s/%s/%s" % (contents_file, conf.datapath, r, uid))
		else:
			if r != "daemon":
				sendErrorMail("no such recipient", (sender, r + "@" + conf.localdomain, getHead(contents_file)))

class QueueProcessThread(threading.Thread):
	def __init__(self, mailid, sender, recipients):
		threading.Thread.__init__(self)
		self.mailid = mailid
		self.sender = sender
		self.recipients = recipients
	
	def run(self):
		log(2, "Queue processor: thread started for processing mail " + self.mailid)
		time.sleep(5)
		msgid = self.mailid
		sender = self.sender
		recipients = self.recipients
		log(2, "Queue processor: processing %s : %s => %s" % (msgid, sender, repr(recipients)))
		file = conf.datapath + "/queued-" + msgid
		for domain in recipients:
			if domain == conf.localdomain or domain == "localhost" or domain == "localdomain":
				deliverLocalMail(sender, recipients[domain], file, msgid)
				log(2, "Queue processor: local mail %s delivered to %s" % (msgid, ",".join(recipients[domain])))
			else:
				rcpts = []
				for r in recipients[domain]:
					rcpts.append(r + '@' + domain)
				ok = 0
				if conf.usesmtprelay == 0:
					mxs = mxServer(domain)
					for i in range(0, 100):
						if ok == 0:
							for mx in mxs:
								if mx[2] == i:
									if smtpSendMail(mx[0], sender, rcpts, file) == 1:
										log(2, "Queue processor: mail %s sent to %s for %s." % (msgid, mx[0], ",".join(rcpts)))
										ok = 1
										break
				if ok == 0:
					if smtpSendMail(conf.smtprelay, sender, rcpts, file) == 0:
						sendErrorMail("cannot deliver", (sender, rcpts, getHead(file)))
						log(1, "Queue processor: mail %s : deliver failed for %s." % (msgid, ",".join(rcpts)))
					else:
						log(2, "Queue processor: mail %s relayed to %s for %s." % (msgid, conf.smtprelay, ",".join(rcpts)))
		os.remove(file)

class SmtpServerThread(threading.Thread):
	def __init(self):
		threading.Thread.__init__(self)
	
	def run(self):
		log(2, "SMTP server: listening thread started")
		while self.running == 1:
			connection, address = smtpsock.accept()
			if self.running == 0:
				connection.close()
				break
			th = SmtpClientThread(connection, address)
			th.start()
			name = th.getName()
			smtpclients[name] = connection
			log(2, "SMTP server: entering connection from %s" % (address[0]))
			connection.send("220 %s SMTP pymaild\n" % (conf.serverhostname))
		smtpsock.close()
		smtpsock.shutdown()
		log(2, "SMTP server: listening thread stopped")

class SmtpClientThread(threading.Thread):
	def __init__(self, conn, addr):
		threading.Thread.__init__(self)
		self.connection = conn
		self.addr = addr

	def run(self):
		clientMsg = "."
		name = self.getName()
		step = 0
		mailfrom = ""
		recipients = {}
		host = reverseDNS(self.addr[0])
		username = host 
		while step == 0 and not clientMsg == "":
			clientMsg = sockReadLine(self.connection).lower()
			if clientMsg == "":
				break
			elif clientMsg == "quit":
				self.connection.send("221 closing connection\r\n")
				clientMsg = ""
				break
			elif clientMsg[:5] in ["ehlo ", "helo "]:
				step = 1
				self.connection.send("250-%s\r\n" % (conf.serverhostname))
				self.connection.send("250-PIPELINING\r\n")
				self.connection.send("250-SIZE %i\r\n" % (conf.smtpmaxmailsize))
				if conf.requireauth != 0:
					self.connection.send("250-AUTH PLAIN LOGIN\r\n")
				self.connection.send("250-8BITMIME\r\n")
				self.connection.send("250 XFILTERED\r\n")
				username = clientMsg.split(" ")[1]
				log(2, "SMTP server: %s (%s) ehloed as %s" % (self.addr[0], host, username))
			elif clientMsg[:4] in ["auth", "mail", "rcpt", "data"]:
				self.connection.send("503 Error: polite people say hello\r\n")
			else:
				self.connection.send("502 Error: unknown command\r\n")

		if (conf.requireauth == 0 and step == 1) or host in conf.noauthhosts or self.addr[0] in conf.noauthhosts:
			step = 2
				
		while step == 1 and not clientMsg == "":
			clientMsg = sockReadLine(self.connection).lower()
			if clientMsg == "":
				break
			elif clientMsg == "quit":
				self.connection.send("221 closing connection\r\n")
				clientMsg = ""
				break
			elif clientMsg == "auth plain":
				self.connection.send("334 \r\n")
				l = base64.b64decode(sockReadLine(self.connection)).split("\0")
				username = l[1]
				password = l[2]
				if authenticate(username, hashlib.md5(password).hexdigest()) == 1:
					step = 2
					self.connection.send("235 plain authentication successfull\r\n")
				else:
					self.connection.send("503 Error: authentication failed\r\n")
			elif clientMsg == "auth login":
				self.connection.send("334 %s\r\n" % (base64.b64encode("Username:")))
				username = base64.b64decode(sockReadLine(self.connection))
				self.connection.send("334 %s\r\n" % (base64.b64encode("Password:")))
				password = base64.b64decode(sockReadLine(self.connection))
				if authenticate(username, hashlib.md5(password).hexdigest()) == 1:
					step = 2
					self.connection.send("235 plain authentication successfull\r\n")
				else:
					self.connection.send("503 Error: authentication failed\r\n")
			elif clientMsg[:4] in ["mail", "rcpt", "data"]:
				self.connection.send("503 Error: must authenticate to send mail.\r\n")
			else:
				self.connection.send("502 Error: unknown command\r\n")

		while step == 2 and not clientMsg == "":
			clientMsg = sockReadLine(self.connection).lower()
			if clientMsg == "":
				break
			elif clientMsg == "quit":
				self.connection.send("221 closing connection\r\n")
				clientMsg = ""
				break
			elif clientMsg[:10] == "mail from:":
				if mailfrom == "":
					clientMsg = clientMsg.split('<')
					if len(clientMsg) < 2:
						self.connection.send("503 Error: bad syntax")
					else:
						clientMsg = clientMsg[1].split('>')[0]
					if isValidAddress(clientMsg) == 0:
						self.onnection.send("504 <%s>: Sender address rejected: need fully-qualified address\r\n" % (clientMsg))
					else:
						mailfrom = clientMsg
						self.connection.send("250 Ok\r\n")
				else:
					self.connection.send("503 Error: nested MAIL command\r\n")
			elif clientMsg[:8] == "rcpt to:":
				if mailfrom == "":
					self.connection.send("503 Error: need MAIL command\r\n")
				else:
					clientMsg = clientMsg.split('<')
					if len(clientMsg) < 2:
						self.connection.send("503 Error: bad syntax")
					else:
						clientMsg = clientMsg[1].split('>')[0]
					if isValidAddress(clientMsg) == 0:
						self.connection.send("504 <%s>: Recipient address rejected: need fully-qualified address\r\n" % (clientMsg))
					else:
						s = clientMsg.split('@')
						if s[1] in recipients:
							recipients[s[1]].append(s[0])
						else:
							recipients[s[1]] = [s[0]]
						self.connection.send("250 Ok\r\n")
			elif clientMsg == "data":
				if mailfrom == "":
					self.connection.send("503 Error: need MAIL command\r\n")
				elif len(recipients) == 0:
					self.connection.send("503 Error: no valid recipients\r\n")
				else:
					self.connection.send("354 End data with <CRLF>.<CRLF>\r\n")
					data = ""
					f = ""
					while 1:
						a = self.connection.recv(1)
						if a == "":
							self.connection.close()
							clientMsg = ""
							break
						else:
							if len(data) > conf.smtpmaxmailsize:
								f = f + a
								if len(f) > 10:
									f = f[1:]
								if f[-5:] == "\r\n.\r\n":
									break
							else:
								data += a
							if len(data) > 10 and data[-5:] == "\r\n.\r\n":
								break
					if not clientMsg == "":
						if len(data) > conf.smtpmaxmailsize:
							self.connection.send("523 Error: message to big (size limit is %i)\r\n" % (conf.smtpmaxmailsize))
							log(2, "SMTP server: %s sent too big mail, mail refused." % (self.addr[0]))
						else:
							mailid = queueMail(mailfrom, recipients, data, (username, host, self.addr[0]))
							self.connection.send("250 OK, queued as %s\r\n" % (mailid))
							log(2, "SMTP server: %s sent mail, queued as %s" % (self.addr[0], mailid))
						mailfrom = ""
						recipients = {}
			else:
				self.connection.send("502 Error: unknown command\r\n")

		log(2, "SMTP server: end transaction with " + self.addr[0])
		self.connection.close()
		del smtpclients[name]

class Pop3ServerThread(threading.Thread):
	def __init(self):
		threading.Thread.__init__(self)
	
	def run(self):
		log(2, "POP3 server: listening thread started")
		while self.running == 1:
			connection, address = pop3sock.accept()
			if self.running == 0:
				connection.close()
				break
			th = Pop3ClientThread(connection, address)
			th.start()
			name = th.getName()
			pop3clients[name] = connection
			log(2, "POP3 server: entering connection from %s" % (address[0]))
			connection.send("+OK POP3 ready\n")
		pop3sock.close()
		pop3sock.shutdown()
		log(2, "POP3 server: listening thread stopped")

class Pop3ClientThread(threading.Thread):
	def __init__(self, conn, addr):
		threading.Thread.__init__(self)
		self.connection = conn
		self.addr = addr

	def run(self):
		clientMsg = "."
		name = self.getName()
		step = 0
		username = ""
		
		while step == 0 and clientMsg != "":
			clientMsg = sockReadLine(self.connection).lower()
			log(3, clientMsg)
			if clientMsg == "":
				break
			elif clientMsg == "quit":
				self.connection.send("+OK\r\n")
				clientMsg = ""
				break
			elif clientMsg == "capa":
				self.connection.send("+OK Capability list follows\r\nTOP\r\nUSER\r\nUIDL\r\n.\r\n")
			elif clientMsg[:5] == "user ":
				if username == "":
					username = clientMsg[5:]
					self.connection.send("+OK\r\n")
				else:
					self.connection.send("-ERR Username already sent.\r\n")
			elif clientMsg[:5] == "pass ":
				if username == "":
					self.connection.send("-ERR invalid command\r\n")
				else:
					password = hashlib.md5(clientMsg[5:]).hexdigest()
					if authenticate(username, password) == 1:
						step = 1
						self.connection.send("+OK\r\n")
						log(2, "POP3 server: %s authed as %s" % (self.addr[0], username))
					else:
						clientMsg = ""
						self.connection.send("-ERR authentication failed\r\n")
						log(2, "POP3 server: %s failed to auth as %s" % (self.addr[0], username))
						break
			else:
				log(3, "POP3 server: %s sent invalid command : %s" % (self.addr[0], clientMsg))
				self.connection.send("-ERR invalid command\r\n")

		maildir = conf.datapath + "/" + username + "/"
		if step == 1:
			file = open(maildir + "mail", "r")
			mail = []
			for a in file.readlines():
				mail.append([a[:-1], os.path.getsize(maildir + a[:-1]), 0])
			file.close()

		while step == 1 and clientMsg != "":
			clientMsg = sockReadLine(self.connection).lower()
			log(3, clientMsg)
			if clientMsg == "":
				break
			elif clientMsg == "quit":
				self.connection.send("+OK\r\n")
				clientMsg = ""
				break
			elif clientMsg == "stat":
				nummsgs = 0
				totalsize = 0
				for m in mail:
					if m[2] == 0:
						nummsgs += 1
						totalsize += m[1]
				self.connection.send("+OK %i %i\r\n" % (nummsgs, totalsize))
			elif clientMsg[:5] == "retr ":
				id = int(clientMsg.split(' ')[1]) - 1
				if mail[id][2] == 0:
					self.connection.send("+OK %i octets\r\n" % (mail[id][1]))
					file = open(maildir + mail[id][0], "r")
					while 1:
						l = file.readline()
						self.connection.send(l)
						if l == ".\r\n" or l == ".\n":
							break
						if l == "":
							self.connection.send("\r\n.\r\n")
							break
					file.close()
				else:
					self.connection.send("-ERR Message deleted\r\n")
			elif clientMsg[:5] == "dele ":
				id = int(clientMsg.split(' ')[1]) - 1
				if mail[id][2] == 0:
					mail[id][2] = 1
					self.connection.send("+OK message %i deleted\r\n" % (id))
				else:
					self.connection.send("-ERR Message deleted\r\n")
			elif clientMsg == "uidl":
				self.connection.send("+OK\r\n")
				for i in range(0, len(mail)):
					if mail[i][2] == 0:
						self.connection.send("%i %s\r\n" % (i + 1, mail[i][0]))
				self.connection.send(".\r\n")
			elif clientMsg[:5] == "uidl ":
				id = int(clientMsg.split(' ')[1]) - 1
				if mail[id][2] == 0:
					self.connection.send("+OK %i %s\r\n" % (id + 1, mail[id][0]))
				else:
					self.connection.send("-ERR Message deleted\r\n")
			elif clientMsg == "list":
				self.connection.send("+OK\r\n")
				for i in range(0, len(mail)):
					if mail[i][2] == 0:
						self.connection.send("%i %i\r\n" % (i + 1, mail[i][1]))
				self.connection.send(".\r\n")
			elif clientMsg[:5] == "list ":
				id = int(clientMsg.split(' ')[1]) - 1
				if mail[id][2] == 0:
					self.connection.send("+OK %i %i\r\n" % (id + 1, mail[id][1]))
				else:
					self.connection.send("-ERR Message deleted\r\n")
			elif clientMsg[:4] == "top ":
				s = clientMsg.split(' ')
				id = int(s[1]) - 1
				if len(s) > 2:
					n = int(s[2])
				else:
					n = -1
				c = -1
				if mail[id][2] == 0:
					self.connection.send("+OK %i octets\r\n" % (mail[id][1]))
					file = open(maildir + mail[id][0], "r")
					while 1:
						l = file.readline()
						connection.send(l)
						if l == ".\r\n" or l == ".\n":
							break
						if l == "":
							connection.send("\r\n.\r\n")
							break
						if c == 0:
							connection.send("\r\n.\r\n")
							break
						if c < 0 and len(l) < 3:
							c = n
						else:
							c -= 1
					file.close()
				else:
					self.connection.send("-ERR Message deleted\r\n")
			elif clientMsg == "rset":
				for i in range(0, len(mail)):
					mail[i][2] = 0
				self.connection.send("+OK\r\n")
			else:
				log(3, "POP3 server: %s sent invalid command : %s" % (self.addr[0], clientMsg))
				self.connection.send("-ERR invalid command\r\n")
				

		log(2, "POP3 server: end transaction with " + self.addr[0])
		self.connection.close()
		if step == 1:
			file = open(maildir + "mail", "w")
			for m in mail:
				if m[2] == 0:
					file.write(m[0] + "\n")
				else:
					os.remove(maildir + m[0])
			file.close()
		del pop3clients[name]

action = ""

username = ""
password = ""

for a in sys.argv:
	if a in ['start', 'stop', 'adduser', 'rmuser', 'updatemx']:
		action = a
	if a[:11] == "--username=":
		username = a[11:]
	if a[:11] == "--password=":
		password = a[11:]

if action == 'stop':
	if os.path.exists(conf.datapath + "/pid"):
		pidfile = open(conf.datapath + "/pid")
		pid = int(pidfile.read())
		pidfile.close()
		os.remove(conf.datapath + "/pid")
		print "Waiting for PyMaild to stop..."
		time.sleep(10)
		os.kill(pid, 15)
		sys.exit(0)
	else:
		print "PyMaild is not running."
		sys.exit(1)
elif action == 'updatemx':
	if os.path.exists(conf.datapath + "/mxservers"):
		mxlist = open(conf.datapath + "/mxservers", "r")
		mxoldlist = eval(mxlist.read())
		mxlist.close()
		mxServers = {}
		for a in mxoldlist:
			print "Updating MX server list for " + a
			b = mxServer(a)
		mxlist = open(conf.datapath + "/mxservers", "w")
		mxlist.write(repr(mxServers).replace('), ', '),\n  ').replace('], ', '],\n ').replace(':', ':\n') + "\n")
		mxlist.close()
elif action == "adduser":
	if username == "":
		username = raw_input("Username : ")
	if username == "":
		print "Invalid username."
		sys.exit()
	username = username.lower()
	ulist = open(conf.datapath + "/users", "r")
	for a in ulist.readlines():
		if a.split(':')[0] == username:
			print "User already exists."
			sys.exit()
	ulist.close()
	if password == "":
		password = raw_input("Password : ")
	if password == "":
		print "Invalid password."
		sys.exit()
	ulist = open(conf.datapath + "/users", "a")
	ulist.write(username + ":" + hashlib.md5(password).hexdigest() + "\n")
	ulist.close()
	os.mkdir(conf.datapath + "/" + username)
	os.system("touch %s/%s/mail" % (conf.datapath, username))
	print "User added."
elif action == "rmuser":
	if username == "":
		print "You must specify username."
		sys.exit()
	username = username.lower()
	ulist = open(conf.datapath + "/users", "r")
	list = ulist.readlines()
	ulist.close()
	ulist = open(conf.datapath + "/users", "w")
	ok = 0
	for u in list:
		if u.split(':')[0] == username:
			print "User deleted."
			ok = 1
		else:
			ulist.write(u)
	ulist.close()
	if ok == 0:
		print "No such user."
	else:
		os.system("rm -rf %s/%s" % (conf.datapath, username))
elif action == 'start':
	if os.path.exists(conf.datapath + "/pid"):
		print "PyMaild is already running. Run 'pymaild.py stop' to stop it."
		sys.exit(1)
	pid = os.fork()
	if pid != 0:
		time.sleep(1)
		if os.path.exists(conf.datapath + "/pid"):
			f = open(conf.datapath + "/pid")
			pid2 = int(f.read())
			f.close()
			if (pid == pid2):
				print "PyMaild started, PID is %i" % (pid)
				sys.exit(0)
			else:
				print "FATAL UNKNOWN ERROR."
				sys.exit(1)
		else:
			print "Error while starting PyMaild. Check %s/log for more information." % (conf.datapath)
			sys.exit(1)
	else:
		log(0, " *********  PyMaild 0.1 starting... **********")
		if os.path.exists(conf.datapath + "/mxservers"):
			mxlist = open(conf.datapath + "/mxservers", "r")
			mxServers = eval(mxlist.read())
			mxlist.close
		else:
			mxServers = {}

		smtpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			smtpsock.bind((conf.serverhost, conf.smtpserverport))
		except socket.error:
			log(1, "Error while binding SMTP server socket on port %i." % (conf.smtpserverport))
			sys.exit()
		log(2, "SMTP server: ready, listening on port %i." % (conf.smtpserverport))
		smtpsock.listen(5)
		smtpclients = {}
		smtpserv = SmtpServerThread()
		smtpserv.running = 1
		smtpserv.start()

		pop3sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			pop3sock.bind((conf.serverhost, conf.pop3serverport))
		except socket.error:
			log(1, "Error while binding POP3 server socket on port %i." % (conf.pop3serverport))
			sys.exit()
		log(2, "POP3 server: ready, listening on port %i." % (conf.pop3serverport))
		pop3sock.listen(5)
		pop3clients = {}
		pop3serv = Pop3ServerThread()
		pop3serv.running = 1
		pop3serv.start()

		pidfile = open(conf.datapath + "/pid", "w")
		pidfile.write("%i" % (os.getpid()))
		pidfile.close()

		while os.path.exists(conf.datapath + "/pid"):
			time.sleep(1)

		smtpserv.running = 0
		pop3serv.running = 0

		mxlist = open(conf.datapath + "/mxservers", "w")
		mxlist.write(repr(mxServers).replace('), ', '),\n  ').replace('], ', '],\n ').replace(':', ':\n') + "\n")
		mxlist.close()
else:
	print "Usage: pymaild.py start|stop"
	print "\tpymaild.py adduser [--username=<username>] [--password=<password>]"
	print "\tpymaild.py rmuser --username=<username>"
	print "\tpymaild.py updatemx"
