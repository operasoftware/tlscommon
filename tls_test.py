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
import probedb.probedata2.models as ProbeData
import tlscommon.mail_test as MailTest
import socket
import time
import errno

def TestConnectionV3(self, rec_version, version):
	"""
	Used to quickly establish if the server support SSL/TLS
	without doing a full handshake.
	Modeled on tlslite implementation
	"""
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
	
	if self.protocol in [ProbeData.Server.PROTOCOL_IMAP, ProbeData.Server.PROTOCOL_SMTP, ProbeData.Server.PROTOCOL_POP]:
		try:
			if self.protocol == ProbeData.Server.PROTOCOL_IMAP:
				MailTest.do_imap_start(sock, True, debug=self.debug)
			elif self.protocol == ProbeData.Server.PROTOCOL_SMTP:
				MailTest.do_smtp_start(sock, True, debug=self.debug)
			elif self.protocol == ProbeData.Server.PROTOCOL_POP:
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
		

	clientRandom = getRandomBytes(32)
	clientHello = ClientHello() 
	clientHello.create(version, clientRandom,
					   createByteArraySequence([]), 
					   list(set(CipherSuite.lessLikelyUnsupportedSuites + CipherSuite.likelyUnsupportedSuites + 
							 	CipherSuite.unsupportedSuites +  CipherSuite.rsaSuites)),
					   [CertificateType.x509], None,
					   self.servername, False,
					   True,
					   None, 
					   send_certstatus= False,
					   renegotiating = False)
	
	ch_bytes = clientHello.write()
	
	s = bytesToString(concatArrays(createByteArraySequence([ContentType.handshake, version[0], version[1], ((len(ch_bytes)>>8) &0xff), len(ch_bytes) & 0xff]), ch_bytes))

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
	recordHeaderLength = 3
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
			return False

		bytes += stringToBytes(s)
		if len(bytes)==3:
			if bytes[0] in ContentType.all:
				recv_ver = (bytes[1], bytes[2]) 
				return (recv_ver >=(3,0) and recv_ver <=version)
			else:
				return False
		if len(bytes) == recordHeaderLength:
			break

	sock.close()
	return False
