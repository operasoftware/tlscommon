# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; -*-
#   Copyright 2010-2012 Opera Software ASA 
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


from tlslite.api import *
from tlslite import constants
from tlslite.constants import *
from tlslite.messages import *
import tlslite.utils.sha256 as sha256
from tlslite.utils.compat import *
from tlslite.utils.cryptomath import *
from tlslite.errors import *
import socket
import time
import errno
import mail_test as MailTest

# Perform a rudimentary client hello, server hello exchange in SSL v2, 
# to determine if the server accepts SSL v2
# Modeled on tlslite implementation

class SSLv2_ClientHello(Msg):
	"""Perform a rudimentary SSL v2 Client Hello""" 
	SSL_CK_RC4_128_WITH_MD5	=		0x010080
	SSL_CK_RC4_128_EXPORT40_WITH_MD5 =	0x020080
	SSL_CK_RC2_128_CBC_WITH_MD5	=	0x030080
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 =	0x040080
	SSL_CK_IDEA_128_CBC_WITH_MD5 =		0x050080
	SSL_CK_DES_64_CBC_WITH_MD5 =		0x060040
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5 =	0x0700C0
	
	SSL_v2_CIPHERS = [
								SSL_CK_RC4_128_WITH_MD5	,
								SSL_CK_RC2_128_CBC_WITH_MD5,
								SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
								SSL_CK_DES_64_CBC_WITH_MD5,
								SSL_CK_RC4_128_EXPORT40_WITH_MD5,
								SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,					
							]

	SSL_v2_CIPHERS_toText = {
								SSL_CK_RC4_128_WITH_MD5:"SSLV2_CK_RC4_128_WITH_MD5"	,
								SSL_CK_RC2_128_CBC_WITH_MD5:"SSLV2_CK_RC2_128_CBC_WITH_MD5",
								SSL_CK_DES_192_EDE3_CBC_WITH_MD5:"SSLV2_CK_DES_192_EDE3_CBC_WITH_MD5",
								SSL_CK_DES_64_CBC_WITH_MD5:"SSLV2_CK_DES_64_CBC_WITH_MD5",
								SSL_CK_RC4_128_EXPORT40_WITH_MD5:"SSLV2_CK_RC4_128_EXPORT40_WITH_MD5",
								SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5:"SSLV2_CK_RC2_128_CBC_EXPORT40_WITH_MD5",					
							}
	
	SSL_v2_CIPHERS_fromText = {
								"SSLV2_CK_RC4_128_WITH_MD5":SSL_CK_RC4_128_WITH_MD5,
								"SSLV2_CK_RC2_128_CBC_WITH_MD5":SSL_CK_RC2_128_CBC_WITH_MD5,
								"SSLV2_CK_DES_192_EDE3_CBC_WITH_MD5":SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
								"SSLV2_CK_DES_64_CBC_WITH_MD5":SSL_CK_DES_64_CBC_WITH_MD5,
								"SSLV2_CK_RC4_128_EXPORT40_WITH_MD5":SSL_CK_RC4_128_EXPORT40_WITH_MD5,
								"SSLV2_CK_RC2_128_CBC_EXPORT40_WITH_MD5":SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,					
							}
	
	SSL_v2_EXPORT_CIPHERS = [
								SSL_CK_DES_64_CBC_WITH_MD5,
								SSL_CK_RC4_128_EXPORT40_WITH_MD5,
								SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,					
							]
	
	SSL_v2_Client_Hello = 1
	
	def __init__(self, settings):
		self.client_version = settings.maxVersion
		self.challenge = createByteArrayZeros(16)+getRandomBytes(16)
		self.session_id = createByteArraySequence([])
		cipherSuites = settings.ciphersuites
		if not cipherSuites:
			cipherSuites = []
			if settings.maxVersion >= (3,3):
				cipherSuites += CipherSuite.tls_1_2Suites
			cipherSuites += CipherSuite.getRsaSuites(settings.cipherNames)
		self.cipher_suites = (		 # a list of 24-bit values
							[CipherSuite.TLS_RENEGO_PROTECTION_REQUEST]+
							(cipherSuites if settings.maxVersion >= (3,0) else []) + 
							SSLv2_ClientHello.SSL_v2_CIPHERS 
							)
		self.use_renego = False

	def write(self, trial=False):
		"""Write the Client Hello"""
		w = Msg.preWrite(self, trial)
		
		w.add(SSLv2_ClientHello.SSL_v2_Client_Hello, 1)
		
		w.add(self.client_version[0], 1)
		w.add(self.client_version[1], 1)
		
		w.add(len(self.cipher_suites)*3, 2)
		w.add(len(self.session_id), 2)
		w.add(len(self.challenge), 2)
		
		w.addFixSeq(self.cipher_suites, 3)
		w.addFixSeq(self.session_id, 1)
		w.addFixSeq(self.challenge, 1)
		
		if trial:
			return w.index
		else:
			return w.bytes
		
class SSLv2_ServerHello(Msg):
	"""Read a SSL v2 Server Hello"""
	SSL_v2_Server_Hello = 4
	
	def __init__(self):
		self.session_id_hit = False
		self.certificate_type = 0
		self.server_version = (0,0)
		self.certificate = None
		self.cipher_specs = None
		self.connection_id = None
		
	def parse(self, p):
		"""Parse the Server Hello""" 
		if p.get(1) != SSLv2_ServerHello.SSL_v2_Server_Hello:
			raise TLSLocalAlert( Alert().create(AlertDescription.unexpected_message, AlertLevel.fatal), "Not SSL v2 Server Hello") 
		self.session_id_hit = p.get(1)
		self.certificate_type = p.get(1)
		self.server_version = (p.get(1), p.get(1))
		certificate_len = p.get(2)
		cipher_len = p.get(2)
		connection_id_len = p.get(2)
		self.certificate = p.getFixBytes(certificate_len)
		self.cipher_specs = p.getFixList(3, int(cipher_len/3))
		self.connection_id = p.getFixBytes(connection_id_len)

PROTOCOL_HTTPS = "HTTPS"   # HTTPS
PROTOCOL_IMAP = "IMAP"	# IMAP STARTTLS
PROTOCOL_IMAP_S = "IMAPS" # IMAP direct TLS
PROTOCOL_SMTP = "SMTP"	# SMTP STARTTLS
PROTOCOL_SMTP_S = "SMTPS"	# SMTP direct TLS
PROTOCOL_POP = "POP"	# POP STARTTLS
PROTOCOL_POP_S = "POPS"	# POP direct TLS

PROTOCOL_START_TLS = (PROTOCOL_IMAP, PROTOCOL_SMTP, PROTOCOL_POP)
PROTOCOL_DIRECT_TLS = (PROTOCOL_HTTPS, PROTOCOL_IMAP_S, PROTOCOL_SMTP_S, PROTOCOL_POP_S)

def TestConnectionV2(self,settings):
	"""Perform a basic test of SSL v2 capability, 
	either with SSLv3+ capability, or SSLv2-only """
	sock = None
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error, error:
		if self.debug: 
			print "Probe: socket create error: ", error.message, "\n"
		return False
	except:
		if self.debug:
			print "\tNo Connection", self.servername, ":", self.port
		if self.available:
			self.unstable = True
		else:
			self.not_available = True
		return False
		
	try:
		sock.settimeout(10)  #Only on python 2.3 or greater
		sock.connect((self.servername, self.port))
		self.available = True
		ip_address = sock.getpeername()[0]
		if ip_address not in self.ip_addresses:
			self.ip_addresses.append(ip_address)
			
	except socket.error, error:
		if self.debug: 
			print "Probe: ", self.servername, ":", self.port, ": Connection Failed socket error: ", error.message, "\n"
		return False
	except:
		if self.debug:
			print "\tNo Connection\n"
		if self.available:
			self.unstable = True
		else:
			self.not_available = True
		return False
	
	if self.protocol in PROTOCOL_START_TLS:
		try:
			if self.protocol == PROTOCOL_IMAP:
				MailTest.do_imap_start(sock, True, debug=self.debug)
			elif self.protocol == PROTOCOL_SMTP:
				MailTest.do_smtp_start(sock, True, debug=self.debug)
			elif self.protocol == PROTOCOL_POP:
				MailTest.do_pop_start(sock, True, debug=self.debug)
		except socket.error, error:
			if self.debug: 
				print "Probe: ", self.servername, ":", self.port, ": StartTLS failed socket error: ", error.message, "\n"
			return False
		except:
			if self.debug:
				print "\tNo Connection\n"
			if self.available:
				self.unstable = True
			else:
				self.not_available = True
			return False


	client_hello = SSLv2_ClientHello(settings)
	
	ch_bytes = client_hello.write()
	
	s = bytesToString(concatArrays(createByteArraySequence([0x80 | ((len(ch_bytes)>>8) &0x7f), len(ch_bytes) & 0xff]), ch_bytes))

	while 1:
		try:
			bytesSent = sock.send(s) #Might raise socket.error
		except socket.error, why:
			if why[0] == errno.EWOULDBLOCK:
				continue
			else:
				return False
		if bytesSent == len(s):
			break
		s = s[bytesSent:]

	bytes = createByteArraySequence([])
	recordHeaderLength = 1
	while 1:
		try:
			s = sock.recv(recordHeaderLength-len(bytes))
		except socket.error, why:
			if why[0] == errno.EWOULDBLOCK:
				continue
			else:
				return False

		#If the connection was abruptly closed, raise an error
		if len(s)==0:
			return (len(bytes) > 0)

		bytes += stringToBytes(s)
		if len(bytes)==1:
			if bytes[0] in ContentType.all:
				# SSLv3+
				self.tolerate_ssl_v2 = True
				if self.only_ssl_v2:
					self.only_ssl_v2 = False
				return True
			elif bytes[0] >= 128:
				self.tolerate_ssl_v2 = True
				if settings.maxVersion >= (3,0):
					self.only_ssl_v2 = True
				recordHeaderLength = 2
			else:
				return True
		if len(bytes) == recordHeaderLength:
			break

	self.supported_versions.append((2,0))
	r = RecordHeader2().parse(Parser(bytes))

	#Check the record header fields
	if r.length > 32767:
		raise SyntaxError()

	#Read the record contents
	bytes = createByteArraySequence([])
	while 1:
		try:
			s = sock.recv(r.length - len(bytes))
		except socket.error, why:
			if why[0] == errno.EWOULDBLOCK:
				continue
			else:
				return True

		#If the connection is closed, raise a socket error
		if len(s)==0:
			return True

		bytes += stringToBytes(s)
		if len(bytes) == r.length:
			break

	try:
		r = SSLv2_ServerHello()
		r.parse(Parser(bytes))
	except:
		return True 

			
	if not self.support_v2_export_ciphers:
		self.support_v2_export_ciphers = any([x in SSLv2_ClientHello.SSL_v2_EXPORT_CIPHERS for x in r.cipher_specs])
	self.support_v2_ciphers.update([SSLv2_ClientHello.SSL_v2_CIPHERS_toText[x] for x in r.cipher_specs if x in SSLv2_ClientHello.SSL_v2_CIPHERS])
	if not self.return_unexpected_v2_ciphers:
		self.return_unexpected_v2_ciphers = any([x not in SSLv2_ClientHello.SSL_v2_CIPHERS for x in r.cipher_specs])
	if r.certificate_type == 0x01 and r.certificate and not self.certificates:
		x509 = X509()
		x509.parseBinary(r.certificate)
		self.certificates = {
			"certificate_list": [{
				"common-name":x509.getCommonName(),
				"finger-print":x509.getFingerprint(sha256.sha256),
				"binary certificate": x509.bytes
								 }],
			"raw_certificate":r.certificate,
			}
	
	sock.close()
	return True
