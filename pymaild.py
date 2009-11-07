#!/usr/bin/env python
import socket, sys, os, threading, base64, hashlib, time, sqlite3
from datetime import datetime

def loadConf(file):
	c = {}
	f = open(file, "r")
	for l in f.readlines():
		if l[0] != "#" and len(l) > 3:
			s = l.split("=")
			name = s[0]
			while name[-1] == " " or name[-1] == '\t':
				name = name[:-1]
			val = eval("=".join(s[1:]))
			c[name] = val
	f.close()
	return c

conf = loadConf("/home/mail/pymaild.conf")

def createDataBase():
	db = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
	db.execute("""CREATE TABLE users (
	name VARCHAR (20) PRIMARY KEY,
	password VARCHAR(51))""")
	db.execute("""CREATE TABLE options (
	id INTEGER PRIMARY KEY,
	user VARCHAR (20),
	name VARCHAR (40),
	value VARCHAR(40))""")
	db.execute("""CREATE TABLE lists (
	id INTEGER PRIMARY KEY,
	name VARCHAR (20))""")
	db.execute("""CREATE TABLE mxservers (
	id INTEGER PRIMARY KEY,
	name VARCHAR (30),
	ip VARCHAR(15),
	domain VARCHAR(30),
	priority INTEGER)""")
	db.execute("""CREATE TABLE user_mail (
	id INTEGER PRIMARY KEY,
	user VARCHAR (20),
	size INTEGER)""")
	db.execute("""CREATE TABLE list_mail (
	id INTEGER PRIMARY KEY,
	list INTEGER,
	mail_id VARCHAR (255),
	subject VARCHAR (255),
	reply_to INTEGER,
	root_message INTEGER,
	sender VARCHAR (100))""")
	db.execute("""CREATE TABLE list_subscribers (
	id INTEGER PRIMARY KEY,
	list INTEGER,
	email VARCHAR (100))""")
	#create some indexes
	db.execute("CREATE INDEX l_name ON lists (name)")
	db.execute("CREATE INDEX lm_list ON list_mail (list)")
	db.execute("CREATE INDEX lm_mail_id ON list_mail (mail_id)")
	db.execute("CREATE INDEX lm_parent ON list_mail (reply_to)")
	db.execute("CREATE INDEX ls_email ON list_subscribers (email)")
	db.execute("CREATE INDEX m_domain ON mxservers (domain)")
	db.execute("CREATE INDEX o_user ON options (user)")
	db.execute("CREATE INDEX um_user ON user_mail (user)")
	db.execute("CREATE INDEX user ON users (name, password)")
	#let's insert some stuff
	db.execute("INSERT INTO options(user, name, value) VALUES(?, ?, ?)", ("", "mailboxsize", "10000000",))
	db.commit()
	db.close()


def log(level, message):
	if level <= conf['loglevel']:
		logfile = open(conf['logfile'], "a")
		l = ['System', 'Error', 'Information', 'Debug'][level]
		logfile.write('%i %s : %s\n' % (int(time.time()), l, message))
		logfile.close()

def sockReadLine(aconnection):
	line = ""
	while 1:
		try :
			a = aconnection.recv(1)
			if a == "\n":
				break
			else:
				line += a
		except:
			aconnection.close()
			return ""
	while line[-1:] == "\r" or line[-1:] == "\n":
		line = line[:-1]
	return line

def authenticate(username, password):
	database = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
	if database.execute("SELECT * FROM users WHERE name=? AND password=?", (username, password,)).fetchone() != None:
		database.close()
		return 1
	database.close()
	return 0

def userConf(username):
	database = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
	ret = {}
	for line in database.execute("SELECT name, value FROM options WHERE user=?", (username,)):
		ret[line[0]] = eval(line[1])
	database.close()
	return ret

def getMailBoxInfo(username):
	database = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
	info = database.execute("SELECT COUNT(id), SUM(size) FROM user_mail WHERE user=?", (username,)).fetchone()
	database.close()
	return info

def isValidAddress(emailaddr):
	if " " in emailaddr or "/" in emailaddr or "&" in emailaddr:
		return 0
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
	if ' ' in ipaddr or '/' in ipaddr or '&' in ipaddr:
		return "0.0.0.0"
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
	if ' ' in hostname or '/' in hostname or '&' in hostname:
		return "0.0.0.0"
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
	if ' ' in domain or '/' in domain or '&' in domain:
		return []
	database = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
	ret = []
	for srv in database.execute("SELECT name, ip, priority FROM mxservers WHERE domain=?", (domain,)):
		ret.append(srv)
	if len(ret) == 0:
		a = os.popen("dig %s MX" % (domain))
		b = a.readlines()
		a.close()
		for l in b:
			if l != "\n" and l[0] != ';':
				t = l.split('\t')[-1]
				h = t.split(' ')[-1][:-2]
				ret.append((h, resolvDNS(h), int(t.split(' ')[-2])))
		if resolvDNS(domain) != "0.0.0.0":
			ret.append((domain, resolvDNS(domain), 90))
		if len(ret) == 0 and conf['smtprelay'] != "":
			ret = [(conf['smtprelay'], resolvDNS(conf['smtprelay']), 99)]
		for l in ret:
			database.execute("INSERT INTO mxservers(name, ip, priority, domain) VALUES(?, ?, ?, ?)", (l[0], l[1], l[2], domain))
		database.commit()
	database.close()
	return ret

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
	contents = contents.split('\r\n')
	headers = []
	headersEnded = False
	for line in contents:
		if not headersEnded:
			if line == "":
				headersEnded = True
			else:
				headers.append(line.split(':')[0].lower())
	file = open(conf['maildir'] + "/queued-" + mailid, "w")
	if not "return-path" in headers:
		file.write("Return-Path: <%s>\r\n" % (sender))
	file.write("Received: from %s (%s [%s])\r\n" % senderinfo)
	file.write("\tby %s (SMTP Server) with SMTP id %s\r\n" % (conf['serverhostname'], mailid))
	while contents[0] != "":
		file.write(contents[0] + "\r\n")
		contents = contents[1:]
	if not "message-id" in headers:
		file.write("Message-Id: <%s@%s>\r\n" % (mailid, conf['serverhostname']))
	if not "date" in headers:
		file.write("Date: %s\r\n" % (datetime.now().strftime("%a,  %d %b %Y %H:%M:%S %z %Z")))
	if not "from" in headers:
		file.write("From: %s\r\n" % (sender))
	if not "to" in headers:
		file.write("To: undisclosed-recipients:;\r\n")
	file.write("\r\n".join(contents))
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
	elif error == "mailbox full":
		subject = "Recipient's mailbox is full"
		recipients = [data[0]]
		message = "Hello\r\n\r\nSorry, mailbox for %s is full, your mail could not be delivered.\r\n" % (data[1])
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
	queueMail("daemon@" + conf['localdomain'], r,
			"From: Mail Delivery Daemon <no-reply@%s>\r\nSubject: %s\r\n\r\n%s" 
			% (conf['localdomain'], subject, message),
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
	csock.send("ehlo %s\r\n" % (conf['serverhostname']))
	log(3, "ehlo %s" % (conf['serverhostname']))
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
	database = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
	size = os.path.getsize(contents_file)
	for r in recipients:
		if database.execute("SELECT name FROM users WHERE name=?", (r,)).fetchone() != None:
			userconf = userConf(r)
			if getMailBoxInfo(r)[0] + size > userconf['mailboxsize']:
				sendErrorMail("mailbox full", (sender, r + "@" + conf['localdomain'], getHead(contents_file)))
			else:
				uid = str(database.execute("INSERT INTO user_mail(user, size) VALUES(?, ?)", (r, size)).lastrowid)
				os.system("cp %s %s/usermail/%s" % (contents_file, conf['maildir'], uid))
		else:
			if r != "daemon":
				sendErrorMail("no such recipient", (sender, r + "@" + conf['localdomain'], getHead(contents_file)))
	database.commit()
	database.close()

def listQueueMail(sender, recipients, contents_file, mailid):
	database = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
	contents = open(contents_file).read().split("\r\n")
	headers = {}
	while len(contents) > 1:
		l = contents[0]
		contents = contents[1:]
		if l == "":
			break
		else:
			if l[0] not in [' ', '\t']:
				headers[l.split(':')[0].lower()] = ':'.join(l.split(':')[1:])[1:]
	contents = "\r\n".join(contents)
	for h in ['recieved', 'to', 'return-path']:
		if h in headers: del headers[h]
	for listname in recipients:
		list = database.execute("SELECT id FROM lists WHERE name=?", (listname, )).fetchone()
		if list == None:
			sendErrorMail("no such recipeint", (sender, listname + "@lists." + conf['localdomain'], getHead(contents_file)))
			continue
		else:
			listid = list[0]
		r = [s[0] for s in database.execute("SELECT email FROM list_subscribers WHERE id=?", (listid, ))]
		if not sender in r:
			continue
		listfile = "%s/queued-%s.%s" % (conf['maildir'], mailid, listname)
		newhead = headers
		if not "[%s]" % (listname) in headers['subject']:
			headers['subject'] = "[%s] %s" % (listname, headers['subject'])
		headers['to'] = "undisclosed-recipients:;"
		headers['Return-Path'] = "<%s@lists.%s>" % (listname, conf['localdomain'])
		headers['Reply-To'] = "<%s@lists.%s>" % (listname, conf['localdomain'])
		file = open(listfile, "w")
		for h in headers:
			file.write("%s%s: %s\r\n" % (h[:1].upper(), h[1:], headers[h]))
		file.write("\r\n")
		file.write(contents)
		file.close()
		recipients = {}
		for rcpt in r:
			rc = rcpt.split("@")
			if len(rc) == 2:
				if rc[1] in recipients:
					recipients[rc[1]].append(rc[0])
				else:
					recipients[rc[1]] = [rc[0]]
		replyto = ""
		if "references" in headers: replyto = headers['references']
		if "in-reply-to" in headers: replyto = headers['in-reply-to']
		if replyto == "":
			replyto = 0
			root_message = 0
		else:
			replyto = database.execute("SELECT id, root_message FROM list_mail WHERE mail_id=?", (replyto, )).fetchone()
			if replyto == None:
				replyto = 0
				root_message = 0
			else:
				root_message = replyto[1]
				replyto = replyto[0]
		id = str(database.execute("INSERT INTO list_mail(list, mail_id, reply_to, sender, subject) VALUES(?, ?, ?, ?, ?)", (listid, headers['message-id'], replyto, sender, headers['subject'])).lastrowid)
		if root_message == 0: root_message = id
		database.execute("UPDATE list_mail SET root_message=? WHERE id=?", (root_message, id,))
		os.system("cp %s %s/listmail/%s" % (listfile, conf['maildir'], id))
		th = QueueProcessThread(mailid + "." + listname, listname + "@lists." + conf['localdomain'], recipients)
		th.start()
	database.commit()
	database.close()

class QueueProcessThread(threading.Thread):
	def __init__(self, mailid, sender, recipients):
		threading.Thread.__init__(self)
		self.mailid = mailid
		self.sender = sender
		self.recipients = recipients
	
	def run(self):
		log(2, "Queue processor: thread started for processing mail " + self.mailid)
		time.sleep(1)
		msgid = self.mailid
		sender = self.sender
		recipients = self.recipients
		log(2, "Queue processor: processing %s : %s => %s" % (msgid, sender, repr(recipients)))
		file = conf['maildir'] + "/queued-" + msgid
		for domain in recipients:
			if domain == conf['localdomain'] or domain == "localhost" or domain == "localdomain":
				deliverLocalMail(sender, recipients[domain], file, msgid)
				log(2, "Queue processor: local mail %s delivered to %s" % (msgid, ",".join(recipients[domain])))
			elif domain == "lists." + conf['localdomain']:
				listQueueMail(sender, recipients[domain], file, msgid)
				log(2, "Queue processor: mail %s queued for mailing list." % (msgid))
			else:
				rcpts = []
				for r in recipients[domain]:
					rcpts.append(r + '@' + domain)
				ok = 0
				if conf['usesmtprelay'] == 0:
					mxs = mxServer(domain)
					for i in range(0, 100):
						if ok == 0:
							for mx in mxs:
								if mx[2] == i:
									if smtpSendMail(mx[0], sender, rcpts, file) == 1:
										log(2, "Queue processor: mail %s sent to %s for %s." % (msgid, mx[0], ",".join(rcpts)))
										ok = 1
										break
				if ok == 0 and conf['smtprelay'] != "":
					if smtpSendMail(conf['smtprelay'], sender, rcpts, file) != 0:
						log(2, "Queue processor: mail %s relayed to %s for %s." % (msgid, conf['smtprelay'], ",".join(rcpts)))
						ok = 1
				if ok == 0:
					sendErrorMail("cannot deliver", (sender, rcpts, getHead(file)))
					log(1, "Queue processor: mail %s : deliver failed for %s." % (msgid, ",".join(rcpts)))
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
			try:
				connection.send("220 %s SMTP pymaild\r\n" % (conf['serverhostname']))
				th = SmtpClientThread(connection, address)
				th.start()
				name = th.getName()
				smtpclients[name] = connection
				log(2, "SMTP server: entering connection from %s" % (address[0]))
			except:
				connection.close()
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
				self.connection.send("250-%s\r\n" % (conf['serverhostname']))
				self.connection.send("250-PIPELINING\r\n")
				self.connection.send("250-SIZE %i\r\n" % (conf['smtpmaxmailsize']))
				if conf['requireauth'] != 0:
					self.connection.send("250-AUTH PLAIN LOGIN\r\n")
				self.connection.send("250-8BITMIME\r\n")
				self.connection.send("250 XFILTERED\r\n")
				username = clientMsg.split(" ")[1]
				log(2, "SMTP server: %s (%s) ehloed as %s" % (self.addr[0], host, username))
			elif clientMsg[:4] in ["auth", "mail", "rcpt", "data"]:
				self.connection.send("503 Error: polite people say hello\r\n")
			else:
				self.connection.send("502 Error: unknown command\r\n")

		authed = False
		if conf['requireauth'] == 0 or host in conf['noauthhosts'] or self.addr[0] in conf['noauthhosts']: authed = True

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
					self.connection.send("235 plain authentication successfull\r\n")
					authed = True
				else:
					self.connection.send("503 Error: authentication failed\r\n")
			elif clientMsg == "auth login":
				self.connection.send("334 %s\r\n" % (base64.b64encode("Username:")))
				username = base64.b64decode(sockReadLine(self.connection))
				self.connection.send("334 %s\r\n" % (base64.b64encode("Password:")))
				password = base64.b64decode(sockReadLine(self.connection))
				if authenticate(username, hashlib.md5(password).hexdigest()) == 1:
					self.connection.send("235 plain authentication successfull\r\n")
					authed = True
				else:
					self.connection.send("503 Error: authentication failed\r\n")
			elif clientMsg == "rset":
				mailfrom = ""
				recipients = {}
				self.connection.send("250 reset ok\r\n")
			elif clientMsg[:5] == "vrfy ":
				who = clientMsg[5:]
				dbase = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
				if dbase.execute("SELECT * FROM users WHERE name=?", (who, )).fetchone() != None:
					self.connection.send("250 %s@%s\r\n" % (who, conf['localdomain'])) 
				else:
					self.connection.send("252 can't tell :/\r\n");
				dbase.close()
			elif clientMsg[:10] == "mail from:":
				if mailfrom == "":
					clientMsg = clientMsg.split('<')
					if len(clientMsg) < 2:
						self.connection.send("503 Error: bad syntax")
					else:
						clientMsg = clientMsg[1].split('>')[0]
					if isValidAddress(clientMsg) == 0:
						self.connection.send("504 <%s>: Sender address rejected: need fully-qualified address\r\n" % (clientMsg))
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
						if s[1] == conf['localdomain'] or s[1] == "lists." + conf['localdomain'] or authed == True:
							if s[1] in recipients:
								recipients[s[1]].append(s[0])
							else:
								recipients[s[1]] = [s[0]]
							self.connection.send("250 Ok\r\n")
						else:
							self.connection.send("504 <%s>: Recipient address rejected: need to be authenticated to send mail to another domain.\r\n" % (clientMsg))
			elif clientMsg == "data":
				if mailfrom == "":
					self.connection.send("503 Error: need MAIL command\r\n")
				elif len(recipients) == 0:
					self.connection.send("503 Error: no valid recipients\r\n")
				else:
					self.connection.send("354 End data with <CRLF>.<CRLF>\r\n")
					data = ""
					f = ""
					file = self.connection.makefile("rb")
					while 1:
						a = file.readline()
						if not a:
							self.connection.close()
							clientMsg = ""
							break
						else:
							if len(data) < conf['smtpmaxmailsize']:
								data += a
							if a[0] == "." and (len(a) == 1 or a[1] in ["\r", "\n"]):
								break
					if not clientMsg == "":
						if len(data) > conf['smtpmaxmailsize']:
							self.connection.send(
								"523 Error: message to big (size limit is %i)\r\n" % 
								(conf['smtpmaxmailsize']))
							log(2, 
								"SMTP server: %s sent too big mail, mail refused." % 
								(self.addr[0]))
						else:
							mailid = queueMail(mailfrom, recipients, data, (username, host, self.addr[0]))
							self.connection.send("250 OK, queued as %s\r\n" % (mailid))
							log(2, "SMTP server: %s sent mail, queued as %s" % (self.addr[0], mailid))
						mailfrom = ""
						recipients = {}
			elif clientMsg == "noop":
				self.connection.send("250 ok no problem ;)\r\n");
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
			try:
				connection.send("+OK POP3 ready\n")
				th = Pop3ClientThread(connection, address)
				th.start()
				name = th.getName()
				pop3clients[name] = connection
				log(2, "POP3 server: entering connection from %s" % (address[0]))
			except:
				connection.close()
		pop3sock.close()
		pop3sock.shutdown()
		log(2, "POP3 server: listening thread stopped")

class Pop3ClientThread(threading.Thread):
	def __init__(self, conn, addr):
		threading.Thread.__init__(self)
		self.connection = conn
		self.addr = addr

	def run(self):
		database = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")
		clientMsg = "."
		name = self.getName()
		step = 0
		username = ""
		
		while step == 0 and clientMsg != "":
			l = sockReadLine(self.connection)
			clientMsg = l.lower()
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
					password = hashlib.md5(l[5:]).hexdigest()
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

		if step == 1:
			mail = []
			for msg in database.execute("SELECT id, size FROM user_mail WHERE user=?", (username, )):
				mail.append([str(msg[0]), msg[1], 0])
			maildir = conf['maildir'] + "/usermail/"

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
					self.connection.send("+OK message %i deleted\r\n" % (id + 1))
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
			for m in mail:
				if m[2] != 0:
					os.remove(maildir + m[0])
					database.execute("DELETE FROM user_mail WHERE id=?", (int(m[0]),))
		database.commit()
		database.close()
		del pop3clients[name]

if not os.path.exists(conf['maildir']):
	os.system("mkdir " + conf['maildir']);
if not os.path.exists(conf['maildir'] + "/usermail"):
	os.system("mkdir " + conf['maildir'] + "/usermail");
if not os.path.exists(conf['maildir'] + "/listmail"):
	os.system("mkdir " + conf['maildir'] + "/listmail");

if not os.path.exists(conf['maildir'] + "/pymaild.sqlite"):
	createDataBase()
db = sqlite3.connect(conf['maildir'] + "/pymaild.sqlite")

action = ""

if len(sys.argv) > 1:
	action = sys.argv[1]

if action == 'stop':
	if os.path.exists(conf['pidfile']):
		pidfile = open(conf['pidfile'])
		pid = int(pidfile.read())
		pidfile.close()
		os.remove(conf['pidfile'])
		print "Waiting for PyMaild to stop..."
		time.sleep(2)
		try:
			os.kill(pid, 15)
		except:
			pass
		sys.exit(0)
	else:
		print "PyMaild is not running."
		sys.exit(1)
elif action == 'updatemx':
	if len(sys.argv) > 2:
		for i in range(2, len(sys.argv)):
			s = sys.argv[i]
			db.execute("DELETE FROM mxservers WHERE domain=?", (i, ))
			db.commit()
			print "Updating MX server list for %s..." % (s)
			b = mxServer(s)
	else:
		mxs = [s[0] for s in db.execute("SELECT domain FROM mxservers GROUP BY domain")]
		db.execute("DELETE FROM mxservers WHERE 1")
		db.commit()
		for s in mxs:
			print "Updating MX server list for %s..." % (s)
			b = mxServer(s)
elif action == "adduser":
	if len(sys.argv) > 2:
		username = sys.argv[2]
	else:
		username = raw_input("Username : ")
	if username == "":
		print "Invalid username."
		sys.exit(1)
	username = username.lower()
	if db.execute("SELECT name FROM users WHERE name=?", (username, )).fetchone() != None:
		print "User already exists."
		sys.exit()
	if len(sys.argv) > 3:
		password = sys.argv[3]
	else:
		password = raw_input("Password : ")
	if password == "":
		print "Invalid password."
		sys.exit(1)
	password =  hashlib.md5(password).hexdigest()
	db.execute("INSERT INTO users(name, password) VALUES(?, ?)", (username, password,))
	for opt in db.execute("SELECT name, value FROM options WHERE user = ?", ("",)):
		db.execute("INSERT INTO options(user, name, value) VALUES(?, ?, ?)", (username, opt[0], opt[1],))
	print "User added."
elif action == "rmuser":
	if len(sys.argv) > 2:
		username = sys.argv[2]
	else:
		print "You must specify username."
		sys.exit(1)
	username = username.lower()
	if db.execute("SELECT name FROM users WHERE name=?", (username, )).fetchone() == None:
		print "User does not exist."
		sys.exit(1)
	db.execute("DELETE FROM users WHERE name=?", (username, ))
	for mail in db.execute("SELECT id FROM user_mail WHERE user=?", (username, )):
		os.remove(conf['maildir'] + "/usermail/%i" % (mail[0]))
		db.execute("DELETE FROM user_mail WHERE ID = ?", mail)
	print "User removed."
elif action == "chpasswd":
	if len(sys.argv) > 2:
		username = sys.argv[2]
	else:
		print "You must specify username."
		sys.exit()
	username = username.lower()
	if db.execute("SELECT name FROM users WHERE name=?", (username, )).fetchone() == None:
		print "User does not exist."
		sys.exit(1)
	if len(sys.argv) > 3:
		password = sys.argv[3]
	else:
		password = raw_input("New password : ")
	if password == "":
		print "Invalid password."
		sys.exit(1)
	password =  hashlib.md5(password).hexdigest()
	db.execute("UPDATE users SET password=? WHERE name=?", (password, username,))
	print "Password changed."
elif action == 'getinfo':
	if len(sys.argv) > 2:
		username = sys.argv[2]
	else:
		print "You must specify username."
		sys.exit(1)
	if db.execute("SELECT * FROM users WHERE name=?", (username, )).fetchone() == None:
		print "Error : no such user"
		sys.exit(1)
	mbinfo = getMailBoxInfo(username)
	userconf = userConf(username)
	print "usedmailbox=%i" % (mbinfo[0])
	print "waitingmails=%i" % (mbinfo[1])
	print "pop3server=%s:%i" % (conf['serverhostname'], conf['pop3serverport'])
	print "smtpserver=%s:%i" % (conf['serverhostname'], conf['smtpserverport'])
	for n in userconf:
		print n + "=" + repr(userconf[n])
elif action == 'chopt' or action == 'chdefaultopt':
	if action == 'chopt':
		if len(sys.argv) > 4:
			username = sys.argv[2]
			option = sys.argv[3]
			value = sys.argv[4]
		else:
			print "Usage :	pymaild.py chopt <username> <option> <new value>"
			sys.exit(1)
	else:
		if len(sys.argv) > 3:
			username = ""
			option = sys.argv[2]
			value = sys.argv[3]
		else:
			print "Usage :	pymaild.py chdefaultopt <option> <new value>"
			sys.exit(1)
	if db.execute("SELECT * FROM users WHERE name=?", (username, )).fetchone() == None:
		print "Error : no such user"
		sys.exit(1)
	e = db.execute("SELECT id FROM options WHERE user=? AND name=?", (username, option,)).fetchone()
	if e == None:
		db.execute("INSERT INTO options(user, name, value) VALUES(?, ?, ?)", (username, option, value))
	else:
		db.execute("UPDATE options SET value=? WHERE id=?", (value, e[0]))
elif action == 'addlist':
	if len(sys.argv) > 2:
		list = sys.argv[2]
	else:
		print "Usage :	pymaild.py addlist <list>"
		sys.exit(1)
	elist = db.execute("SELECT id FROM lists WHERE name = ?", (list,)).fetchone()
	if elist == None:
		db.execute("INSERT INTO lists(name) VALUES(?)", (list,))
		print "Ok"
	else:
		print "Error : lists already exists."
		sys.exit(1)
elif action == 'rmlist':
	if len(sys.argv) > 2:
		list = sys.argv[2]
	else:
		print "Usage :	pymaild.py rmlist <list>"
		sys.exit(1)
	list = db.execute("SELECT id FROM lists WHERE name = ?", (list,)).fetchone()
	if list == None:
		print "Error : list does not exist."
		sys.exit(1)
	listid = list[0]
	db.execute("DELETE FROM list_subscribers WHERE list=?", (listid,))
	for mail in db.execute("SELECT id FROM list_mail WHERE list=?", (listid,)):
		os.remove(conf['maildir'] + "/listmail/%i" % (mail[0]))
	db.execute("DELETE FROM list_mail WHERE list=?", (listid,))
	db.execute("DELETE FROM lists WHERE id=?", (listid,))
	print "Ok"
elif action == 'mlsubscribe':
	if len(sys.argv) > 3:
		list = sys.argv[2]
		email = sys.argv[3]
	else:
		print "Usage:	pymaild.py mlsubscribe <list> <email>"
		sys.exit(1)
	list = db.execute("SELECT id FROM lists WHERE name = ?", (list,)).fetchone()
	if list == None:
		print "Error : no such mailing list."
		sys.exit(1)
	else:
		if db.execute("SELECT id FROM list_subscribers WHERE list=? AND email=?", (list[0], email,)).fetchone() == None:
			db.execute("INSERT INTO list_subscribers(list, email) VALUES (?, ?)", (list[0], email,))
			print "Ok."
		else:
			print "Error : user already subscribed to list."
			sys.exit(1)
elif action == 'mlunsubscribe':
	if len(sys.argv) > 3:
		list = sys.argv[2]
		email = sys.argv[3]
	else:
		print "Usage:	pymaild.py mlunsubscribe <list> <email>"
		sys.exit(1)
	list = db.execute("SELECT id FROM lists WHERE name = ?", (list,)).fetchone()
	if list == None:
		print "Error : no such mailing list."
		sys.exit(1)
	else:
		subscription = db.execute("SELECT id FROM list_subscribers WHERE list=? AND email=?", (list[0], email,)).fetchone()
		if subscription == None:
			print "Error : user not subscribed to list."
			sys.exit(1)
		else:
			db.execute("DELETE FROM list_subscribers WHERE id=?", (subscription[0], ))
			print "Ok."
elif action == 'sendmail':
	args = sys.argv[2:]
	recipients = []
	opt_t = False
	opt_i = False
	while len(args) > 0:
		arg = args[0]
		args = args[1:]
		if arg[0] == "-":
			if arg == "-t": arg_t = True
			if arg == "-i": arg_i = True
		else:
			recipients.append(arg)
	headers = []
	f = False
	contents = ""
	while 1:
		try:
			l = raw_input()
		except:
			break
		if not f:
			if l == "": f = True
			else: headers.append(l)
		else:
			if l == ".":
				if opt_i: l == ".."
				else: break
			contents += l + "\r\n"
	if opt_t:
		nhs = []
		for h in headers:
			if h.lower()[:3] in ['to:', 'cc:']:
				for r in h[3:].split(','): recipients.append(r)
				nhs.append(h)
			elif h.lower()[:4] == "bcc:":
				for r in h[:4].split(','): recipients.append(r)
			else:
				newh.append(h)
		headers = nhs
	rcpts = {}
	for r in recipients:
		while r[0] == ' ': r = r[1:]
		while r[-1] == ' ': r = r[:-1]
		r = r.split('@')
		if len(r) == 2:
			if r[1] in rcpts:
				rcpts[r[1]].append(r[0])
			else:
				rcpts[r[1]] = [r[0]]
	c = ""
	for h in headers:
		c += h + "\r\n"
	c += "\r\n"
	c += contents
	if os.fork() == 0:
		queueMail(conf['sendmailfrom'], rcpts, c, ('localhost', 'localhost', '127.0.0.1'))
elif action == 'start':
	if os.path.exists(conf['pidfile']):
		print "PyMaild is already running. Run 'pymaild.py stop' to stop it."
		sys.exit(1)
	pid = os.fork()
	if pid != 0:
		time.sleep(1)
		if os.path.exists(conf['pidfile']):
			f = open(conf['pidfile'])
			pid2 = int(f.read())
			f.close()
			if (pid == pid2):
				print "PyMaild started, PID is %i" % (pid)
				sys.exit(0)
			else:
				print "FATAL UNKNOWN ERROR."
				sys.exit(1)
		else:
			print "Error while starting PyMaild. Check %s for more information." % (conf['logfile'])
			sys.exit(1)
	else:
		log(0, " *********  PyMaild 0.3 starting... **********")

		smtpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			smtpsock.bind((conf['serverhost'], conf['smtpserverport']))
		except socket.error:
			log(1, "Error while binding SMTP server socket on port %i." % (conf['smtpserverport']))
			sys.exit()
		log(2, "SMTP server: ready, listening on port %i." % (conf['smtpserverport']))
		smtpsock.listen(5)
		smtpclients = {}
		smtpserv = SmtpServerThread()
		smtpserv.running = 1
		smtpserv.start()

		pop3sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			pop3sock.bind((conf['serverhost'], conf['pop3serverport']))
		except socket.error:
			log(1, "Error while binding POP3 server socket on port %i." % (conf['pop3serverport']))
			sys.exit()
		log(2, "POP3 server: ready, listening on port %i." % (conf['pop3serverport']))
		pop3sock.listen(5)
		pop3clients = {}
		pop3serv = Pop3ServerThread()
		pop3serv.running = 1
		pop3serv.start()

		pidfile = open(conf['pidfile'], "w")
		pidfile.write("%i" % (os.getpid()))
		pidfile.close()

		while os.path.exists(conf['pidfile']):
			time.sleep(1)

		smtpsock.close()
		pop3sock.close()

		smtpserv.running = 0
		pop3serv.running = 0
else:
	print "Usage: pymaild.py start|stop"
	print "\tpymaild.py adduser [<username> [<password>]]"
	print "\tpymaild.py rmuser <username>"
	print "\tpymaild.py chpasswd <username> [<new password>]"
	print "\tpymaild.py getinfo <username>"
	print "\tpymaild.py chopt <username> <option> <new value>"
	print "\tpymaild.py addlist <listname>"
	print "\tpymaild.py rmlist <listname>"
	print "\tpymaild.py mlsubscribe <list> <email>"
	print "\tpymaild.py mlunsubscribe <list> <email>"
	print "\tpymaild.py sendmail <options>"
	print "\tpymaild.py updatemx"

db.commit()
db.close()
