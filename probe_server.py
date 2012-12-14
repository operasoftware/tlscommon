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

# Perform a full scan of a SSL/TLS server to determine its capabilities 
# and any potential problems 

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
from tlslite.X509 import X509
from tlslite.X509CertChain import X509CertChain
import tlscommon.ssl_v2_test as SSLv2Test
import tlscommon.mail_test as MailTest
from test_results import *
import tlslite.TestHandshake as TestHandshake 





def print_list(items):
	if items:
		return "\n     " + "\n     ".join(items)
	else:
		return ""

def _build_extension_list(prefix = [], choices = None, original_choices= None):
	
	if choices == None:
		if not original_choices:
			original_choices = ProbeServer.EXTENSION_LIST_CHECKED
		choices =  original_choices
	if not choices:
		return []
	
	list = []
	for choice in choices:
		current_prefix = prefix + [choice]
		if len(current_prefix) == len (original_choices):
			continue # do not check the full list
	
		list += [current_prefix]
		if len(choices) == 1:
			continue

		i = choices.index(choice)
		if i< len(choices):
			list += _build_extension_list(current_prefix, choices[i+1:], original_choices)

	return list

# main engine for testing servers 
class ProbeServer:
	
	EXTENSION_LIST_CHECKED = constants.IndividualExtensionsTested.ALL
	EXTENSION_SET_LIST_CHECKED = _build_extension_list(original_choices = EXTENSION_LIST_CHECKED) 
	
	# List of supported protocols 
	PROTOCOL_HTTPS = "HTTPS"   # HTTPS
	PROTOCOL_IMAP = "IMAP"	# IMAP STARTTLS
	PROTOCOL_IMAP_S = "IMAPS" # IMAP direct TLS
	PROTOCOL_SMTP = "SMTP"	# SMTP STARTTLS
	PROTOCOL_SMTP_S = "SMTPS"	# SMTP direct TLS
	PROTOCOL_POP = "POP"	# POP STARTTLS
	PROTOCOL_POP_S = "POPS"	# POP direct TLS
	
	# All protocols
	PROTOCOLS = (PROTOCOL_HTTPS, PROTOCOL_IMAP_S, PROTOCOL_SMTP_S, PROTOCOL_POP_S, PROTOCOL_IMAP, PROTOCOL_SMTP, PROTOCOL_POP)
	# Protocols that require the STARTTLS protocol 
	PROTOCOL_START_TLS = (PROTOCOL_IMAP, PROTOCOL_SMTP, PROTOCOL_POP)
	# Protocols that start using TLS from first byte
	PROTOCOL_DIRECT_TLS = (PROTOCOL_HTTPS, PROTOCOL_IMAP_S, PROTOCOL_SMTP_S, PROTOCOL_POP_S)
	
	def __init__(self, servername):
		# Information about the servername, and database connection
		self.servername_item = servername
		self.index = servername.id
		self.servername = servername.servername
		self.port=servername.port
		self.protocol = servername.protocol
		
		# registered IP addresses
		self.ip_addresses = []
		self.ip_address_rec = []

		
		#was the server availabel
		self.available = False
		self.not_available = False
		
		# Alexa rating
		self.alexa = -1
		
		#number of connections used to test the server
		self.used_connections = 0


		# Client certificate requested
		self.clientcertificate_requested = False
		#Does the server look like it require a client certificate (always fails if no cert is presented)?  
		self.clientcertificate_required = False
		# test using the Alert message? 
		self.use_no_cert_alert_fallback = False
		# We used the No cert alert message
		self.used_no_cert_alert_fallback = False
		
		self.version_tolerated = []
		self.extension_tolerated = []

		# SSL Session resumability results
		self.tested_session = False
		self.resumable_session = False
		self.resumed_session= False
		# tested resume using the same version indication as in the first Hello?
		self.resumed_session_with_original = False
		# Did we get a new SSL session when using the original version?
		self.new_session_with_original = False
		# Did resuming fail the original version was used?
		self.fail_resumed_session_with_original =False
		#Session ticket tests
		self.sent_session_ticket = False
		self.resumed_session_ticket = False
		
		# Did the server request that the client renegotiate the connection?
		self.requested_renegotiation = None
		# Did the server accept that the client initiated renegotiation?
		self.accepted_renegotiation = None
		# Did the server accept renegotiation if the RI info was faked? Is so, serious trouble
		self.accepted_renegotiation_fake_renego = None
		# Did the server accept a connection being initiated with fake RI info? Is so, serious trouble
		self.accepted_start_fake_renego=None
		# Did the server accept renegotiation if the client indicated the original (higher) version in the premaster?
		self.accepted_renegotiation_higher_premaster =None
		# Did the server accept renegotiation if the client indicated a  version even higher than 
		# the version originally indicated in the premaster?
		self.accepted_renegotiation_even_higher_premaster =None
		# Did renegotiaiton complete?
		self.completed_renegotiation = None
		# Did the server accept the Renego extension and the Renego SCSV in the same handshake?
		self.accepted_renego_ext_and_scsv = None
		
		# Did the server pass all the version/extension tolerance tests?
		self.passed_all = False
		# Did the server pass any of the version/extension tolerance tests?
		self.passed_any = False
		# Did we detect noncompliant results?
		self.non_compliant = False
		
		# List of certificates presented by the server
		self.certificates = []
		# Cipher suites supported
		self.ciphers_supported = []
		# SSL/TLS versions supported
		self.supported_versions= []
		# SSL/TLS versions detected
		self.detected_versions=[]
		# Did the server swap the version numbers from Client Hello and Record Protocol?
		self.detected_ch_version_swap=False
		# Did the server require the version numbers from Client Hello and Record Protocol to be the same?
		self.detected_ch_rec_sameversion=False
		# Is the server extension intolerant
		self.extension_intolerant= False
		# Is the server extension intolerant for SSLv3?
		self.extension_intolerant_v3 = False
		
		# Did the server accept a False Start attempt?
		self.accept_false_start = None
		
		# List of failed version/extension tolerance modes (short and long form)
		self.failed_modes_short = []
		self.failed_modes = []
		
		# List of passed version/extension tolerance modes (short and long form)
		self.passed_modes_short=[]
		self.passed_modes = []
		# List of non-compliant version/extension tolerance modes (short and long form)
		self.non_compliant_modes_short=[]
		self.non_compliant_modes = []
		
		# Did the server support Renego Indication extension
		self.have_renego = False
		# Did the server both indicate RI support and not supporting it? Indicates partial patch status
		self.renego_unstable = False
		
		# Did the server support Server Name Indication?
		self.have_SNI = False
		# Did the server return the Server Name Indication mismatch alert?
		self.sent_SNI_Alert =False
		
		# Did the server return a Certificate Status Extension record? If so, this is the content
		self.certificate_status = None
		
		# Content of the Server Agent HTTP header, or initial content from other protocols, when relevant 
		self.server_agent = None

		# Planned for server name mismatch detection; unused
		self.servername_mismatch = False
		
		# Repeat a version/extension tolerance test this many times if it fails.
		self.maxtest_iterations = 2
		
		# Activate debug logging code?
		self.debug = False
		
		# Did the server have trouble with extra padding in block records?
		self.extra_padding_problems = False

		# SSL v2 test results
		self.support_v2_export_ciphers = False
		self.support_v2_ciphers = set()
		self.return_unexpected_v2_ciphers = False
		self.tolerate_ssl_v2 = False
		self.only_ssl_v2 = False
		
		# Ephemeral DH key size, non-exportable cipher suite
		self.dhe_keysize = 0
		# Ephemeral DH key size, exportable cipher suite
		self.weak_dhe_keysize = 0
		# Did the server support any exportable cipher suites? 
		self.support_weak_ciphers = False

		# Did the server select any cipher suites that are "deprecated" in the selected protocl version?
		self.selected_deprecated_cipher = False
		# Did the server select any cipher suites that is "really" defined for newer protocol versions than the supported version?
		self.selected_cipher_later_version = False

		# Is the server intolerant for specific TLS extensions 
		self.intolerant_for_extension = []
		self.tested_specific_intolerance = False
		# Did the server tolerate extensions for newer version numbers, but not older ones?
		self.reversed_extension_intolerance = False;
		
		# Tested and succeeded when breaking up the application record in two records 
		# first or second being 0, 1 or 2 bytes, broken up in two network packages
		self.working_part_record = None
		# Tested and succeeded when breaking up the application record in two records 
		# first or second being 0, 1 or 2 bytes, collected into a single network package
		self.working_part_record_collect = None
		
		# Collection of test enum flags, listed in test_results.py
		self.test_results = set()
		
	# Print all the findings for the given server
	def __str__(self):
		"""Print content of the test results"""
		
		strng = "servername: " +self.servername +"\n"
		strng += "port: " + str(self.port) +"\n"
		strng += "IP addresses: " + print_list(self.ip_addresses) + "\n"
		if self.server_agent:
			strng += "server-agent: " + self.server_agent + "\n"
		else:
			strng += "server-agent:\n"
			
		if self.alexa >0:
			strng += "alexa: " + str(self.alexa) +"\n"
		strng += "available: " +str(self.available) +"\n"
		strng += "not available: " +str(self.not_available) +"\n"
		strng += "Connections used: " +str(self.used_connections) +"\n"
		
			
		strng += "passed_all: " +str(self.passed_all) +"\n"
		strng += "passed_any: " +str(self.passed_any) +"\n"
		strng += "non_compliant: " + str(self.non_compliant) +"\n"
		strng += "have renego: " + str(self.have_renego) +"\n"
		strng += "unstable renego: " + str(self.renego_unstable) +"\n"
		strng += "intolerant for extension + SCSV: " + str(not self.accepted_renego_ext_and_scsv) +"\n\n"
		
		strng += "Supported versions: " + str(sorted(self.supported_versions)) +"\n\n"
		strng += "Detected versions: " + str(sorted(self.detected_versions)) +"\n\n"
		
		strng += "possible mirror version non-compliant: " + str(any([x not in self.supported_versions for x in self.detected_versions])) +"\n"
		strng += "Detected Client Hello version swap with record protocol: " + str(self.detected_ch_version_swap)  +"\n"
		strng += "Detected Client Hello version must match record protocol: " + str(self.detected_ch_rec_sameversion)  +"\n"
		strng += "Extension tolerant: " +str(not self.extension_intolerant) +"\n"
		strng += "Extension intolerant in v3.0 only: " +str(self.extension_intolerant_v3) +"\n"
		strng += "Extension tolerance reversed for newer versions: " +str(self.reversed_extension_intolerance) +"\n"
		strng += "Did not tolerate extensions: " + str(self.intolerant_for_extension) +"\n\n"
		
		strng += "have SNI: " + str(self.have_SNI) +"\n"
		strng += "Sent SNI alert: " + str(self.sent_SNI_Alert) +"\n\n"
		strng += "Accepted False Start: " + str(self.accept_false_start) +"\n\n"
		
		strng += "Client certificate requested: " + str(self.clientcertificate_requested) + "\n"
		strng += "Client certificate apparently needed: " + str(self.clientcertificate_required) + "\n"
		strng += "Needed to use No Certificate Alert in TLS 1.x: " + str(self.used_no_cert_alert_fallback) + "\n\n"
		
		strng += "Tested session: " + str(self.tested_session) + "\n"
		strng += "Returned Resumable session: " + str(self.resumable_session) + "\n"
		strng += "Resumed session: " + str(self.resumed_session) + "\n"
		strng += "Failed connection when resumed session with original version: " + str(self.fail_resumed_session_with_original) + "\n"
		strng += "Resumed session with original version: " + str(self.resumed_session_with_original) + "\n"
		strng += "New session with original version: " + str(self.new_session_with_original) + "\n\n"
		strng += "Sent Session Ticket: " + str(self.sent_session_ticket) + "\n"
		strng += "Resumed Session ticket: " + str(self.resumed_session_ticket) + "\n\n"

		strng += "Server requested renegotiation: " + str(self.requested_renegotiation) + "\n"
		strng += "Server accepted renegotiation: " + str(self.accepted_renegotiation) + "\n"
		strng += "Server accepted bogus renegotiation: " + str(self.accepted_renegotiation_fake_renego) + "\n" 
		strng += "Server accepted bogus renegotiation at start: " + str(self.accepted_start_fake_renego) + "\n" 
		strng += "Server accepted renegotiation with higher version in premaster: " + str(self.accepted_renegotiation_higher_premaster) + "\n" 
		strng += "Server accepted renegotiation with bogus version in premaster (does not check the version): " + str(self.accepted_renegotiation_even_higher_premaster) + "\n"
		strng += "Server completed request after renegotiation refused: " + str(self.completed_renegotiation)+"\n"
		strng += "\n" 


		strng += "Selected cipher(s) deprecated by version: " + str(self.selected_deprecated_cipher) +"\n"
		strng += "Selected cipher(s) allowed only by newer versions: " + str(self.selected_cipher_later_version) +"\n\n"
		
		strng += "Support only strong ciphers: " + str(not self.support_weak_ciphers) +"\n"
		
		strng += "Tolerate SSLv2: "+ str(self.tolerate_ssl_v2) +"\n"
		strng += "Support only SSL v2: " + str(self.only_ssl_v2) +"\n"

		strng += "Support SSL v2 Export Ciphers: " + str(self.support_v2_export_ciphers) +"\n" 
		strng += "Returned unexpected SSL v2 ciphers: " + str(self.return_unexpected_v2_ciphers) +"\n"

		if self.dhe_keysize:
			strng += "DHE keysize" + str(self.dhe_keysize) +"\n"
		if self.weak_dhe_keysize:
			strng += "Weak DHE keysize" + str(self.weak_dhe_keysize) +"\n"

		strng += "\nExtra padding bytes causes trouble: " + str(self.extra_padding_problems) +"\n\n"
		
		strng += "\nTested limited first payload record: " + str(self.working_part_record) +"\n\n"
		strng += "\nTested limited first payload record with record collection: " + str(self.working_part_record_collect) +"\n\n"

		
		strng += "General testresults: "+ print_list(sorted([TRESULTC_VALUES_dict[x] for x in self.test_results]))+"\n\n"
		
		strng += "failed_modes: "+print_list(self.failed_modes_short) +"\n\n"
		
		strng += "passed modes: "+print_list(self.passed_modes_short) +"\n\n"
		
		strng += "non-compliant modes: "+print_list(self.non_compliant_modes_short) +"\n\n"
		
		if self.certificates:
			if isinstance(self.certificates, dict):
				strng += "certificates: " +print_list([str(x) for x in self.certificates["certificate_list"]]) +"\n"
			else:
				strng += "certificates: " +print_list(self.certificates) +"\n"
		else:
			strng += "certificates: \n" 
		if self.certificate_status:
			strng += "Certificate status: "+ str(self.certificate_status) +"\n"
		else:
			strng += "Certificate status: \n" 
		strng += "ciphers_supported: " +print_list(self.ciphers_supported) +"\n"
		strng += "SSL_v2_ciphers_supported: " +print_list(self.support_v2_ciphers) +"\n"
		strng += "versions_supported: " +print_list([str(x) for x in self.supported_versions]) +"\n"
		strng += "extra_indicated_versions_supported: " +print_list([str(x) + (" (Mismatch)" if x not in self.supported_versions else "") for x in self.detected_versions]) +"\n"

		strng += "failed_modes_long: "
		if any("long_text" in x for x in self.failed_modes):
			strng += print_list([x.get("long_text", None) for x in self.failed_modes]) +"\n"
		else:
			strng += print_list([str(x) for x in self.failed_modes]) +"\n"
		
		strng += "passed modes_long: "
		if any("long_text" in x for x in self.passed_modes):
			strng += print_list([x.get("long_text", None) for x in self.passed_modes]) +"\n"
		else:
			strng += print_list([str(x) for x in self.passed_modes]) +"\n"
		strng += "non-compliant modes: "
		if any("long_text" in x for x in self.non_compliant_modes):
			strng += print_list([x.get("long_text", None) for x in self.non_compliant_modes]) +"\n"
		else:
			strng += print_list([str(x) for x in self.non_compliant_modes]) +"\n"

		strng += "servername mismatch: " + str(self.servername_mismatch) +"\n"
		
		return strng

	# Send a HTTP request to the server	
	def __SendHTTPApplication(self, connection, mode):
		hostport = ""
		if self.port != 443:
			hostport = ":"+str(self.port)
		connection.send((mode.get("check-server") if isinstance(mode.get("check-server"), str) else "GET")+
					" / HTTP/1.1\r\nHost: "+self.servername+hostport+ 
					("\r\nUser-Agent: Opera/9.80 (Windows NT 6.1; U; en) Presto/2.9.199 Version/11.00\r\n"+
					 "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, application/x-obml2d, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\n"+
					 "Accept-Language: nb-NO,nb;q=0.9,no-NO;q=0.8,no;q=0.7,en;q=0.6\r\n"+
					 #"Accept-Encoding: gzip, deflate\r\n"+
					 "Connection: Keep-Alive\r\n\r\n"
					 if mode.get("opera",False) else
					"\r\nUser-Agent: TLSProber/0.8\r\n\r\n"
					)
					)
			
	
	def __DoConnection(self, settings, mode, state, session=None):
		"""
		Perform a single test connection to the server, with the 
		defined settings for the protocol actions, optionally resuming a session
		"""
		 
		sock = None
		if self.debug:
			print mode, "\n"

		#connect to server
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.used_connections += 1
		except socket.error, error:
			if self.debug: 
				print "Probe: socket create error: ", error.message, "\n"
			if mode:
				mode["socket-error"] = str(error)
			return False
		except:
			if self.debug:
				print "\tNo Connection", self.servername, ":", self.port
			if self.available:
				self.unstable = True
			else:
				self.not_available = True
			raise 
			
		try:
			sock.settimeout(10.0)  #Only on python 2.3 or greater
			sock.connect((self.servername, self.port))
			self.available = True
			#collect IP addresses
			ip_address = sock.getpeername()[0]
			if ip_address not in self.ip_addresses:
				self.ip_addresses.append(ip_address)
				
		except socket.error, error:
			if self.debug: 
				print "Probe: ", self.servername, ":", self.port, ": Connection Failed socket error: ", error.message, "\n"
			if mode:
				mode["socket-error"] = str(error)
			return False
		except:
			if self.debug:
				print "\tNo Connection\n"
			if self.available:
				self.unstable = True
			else:
				self.not_available = True
			raise TLSLocalAlert(Alert().create(AlertDescription.unexpected_message, AlertLevel.fatal), "Not SSL v2 ServerHello") 
			
		
		# For ports using START TLS, perform that action now 
		if self.protocol in ProbeServer.PROTOCOL_START_TLS:
			try:
				if self.protocol == ProbeServer.PROTOCOL_IMAP:
					agent = MailTest.do_imap_start(sock, True, debug=self.debug)
				elif self.protocol == ProbeServer.PROTOCOL_SMTP:
					agent = MailTest.do_smtp_start(sock, True, debug=self.debug)
				elif self.protocol == ProbeServer.PROTOCOL_POP:
					agent = MailTest.do_pop_start(sock, True, debug=self.debug)
				state["serveragent"] = agent
			except socket.error, error:
				if self.debug: 
					print "Probe: ", self.servername, ":", self.port, ": StartTLS failed socket error: ", error.message, "\n"
				if mode:
					mode["socket-error"] = str(error)
				return False
			except:
				if self.debug:
					print "\tNo Connection\n"
				if self.available:
					self.unstable = True
				else:
					self.not_available = True
				return False
		
		# Initiate the TLS part of the connection
		try:
			connection = TLSConnection(sock)
			connection.settimeout(10)  #Only on python 2.3 or greater
			if mode and "partial_record" in mode:
				# enable partial application record sending; test ability to handle BEAST workaround  
				connection.use_partial_app_record = True
				connection.part_app_record_len = mode["partial_record"]
				connection.part_app_record_collect = mode.get("partial_record_collect",False)
			if self.protocol == ProbeServer.PROTOCOL_HTTPS and mode and mode.get("false-start",False) and mode.get("check-server", False):
				# Start False Start test
				connection.settimeout(30)  #Only on python 2.3 or greater
				connection.EnableFalseStart(True)
				self.__SendHTTPApplication(connection, mode)
		except:
			raise
		try:
			#Start handshake
			connection.handshakeClientCert(settings = settings,servername = self.servername, session=session)
			
			# Able to connect? What are the properties of the connection?
			
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version

			if settings.ciphersuites and connection.session.cipherSuite not in settings.ciphersuites:
				mode["tls-local-error"] = "Wrong ciphersuite chosen by servers: "+constants.CipherSuite.toText.get(connection.session.cipherSuite,"unknown suite")
				return False 

			state["selected_cipher"] = connection.session.cipherSuite

			if settings.just_test_cipher:
				# If we are just testing cipher suite support, return now
				if  connection.session.test_cipher_selected:
					if connection.session.dhe_keysize:
						if connection.session.cipherSuite not in constants.CipherSuite.weakSuites:
							state["dhe_keysize"]=connection.session.dhe_keysize
						else:
							state["weak_dhe_keysize"]=connection.session.dhe_keysize
					return True
				return False
			

			if self.debug: 
				print self.servername, ":", self.port, ": Negotiated versions %d.%d\n" %(connection.version[0], connection.version[1])
				
			if mode and mode.get("trigger_renegotiation", False):
				for msg in connection.startRenegotiation():
					pass
				if connection._handshake_in_progress:
					raise TLSAbruptCloseError("Renegotiation Failed")
				state["renegotiate_triggered"]= connection.renegotiationStarted
			
			state["session"]= connection.session
			state["version"]= connection.version
			state["cert"]=connection.session.serverCertChain.x509List
			state["raw_certificate"]=connection.session.serverCertChain 
			state["renego_supported"] = connection.session.received_renego_information
			state["SNI_support"]=connection.session.received_SNI_signal
			state["SNI_alert"]=connection.session.received_SNI_alert
			state["certificate_status"] = connection.session.certificateStatusResponse
			
			try:
				if mode and mode.get("check-server", False):
					if self.protocol == ProbeServer.PROTOCOL_HTTPS:
						# send HTTP request, parse response and collect HTTP server information
						if not mode.get("false-start",False): 
							self.__SendHTTPApplication(connection, mode)
						
						response = ""
						try:
							starttime = time.time()
							timeout = 10.0 if not mode.get("false-start",False) else 30.0
							while response.find("\n\n") <0 and response.find("\n\r\n") <0 and time.time()-starttime <timeout:
								response += connection.read()
								time.sleep(0.5)
							if len(response) == 0:
								raise socket.timeout("timeout")
							
						except BaseException, error:
							if connection._handshake_in_progress:
								raise
							if settings.extra_padding_bytes:
								raise
							if connection.renegotiationStarted and settings.refuse_renegotiation:
								raise
							if len(response) == 0:
								raise
							if mode and "partial_record" in mode:
								raise
							if mode.get("false-start",False) and not response:
								raise
								
							pass
						
#						print "----", time.time()-starttime 
#						print response,"<<<", len(response)
#						print "----"
						
						idx = response.find("\n\n")
						if idx < 0:
							idx = response.find("\n\r\n")
						if idx>=0:
							response = response[:idx]

						lines = response.splitlines(False)
						response = lines[0].split()
						if len(response)<2 or not response[0].upper().startswith("HTTP/") or not response[1].isdigit():
							raise BaseException("Bad response")
						state["response"] = int(response[1])
						for line in lines:
							(hdrname,sep,value) = line.partition(":")
							if hdrname.lower() == "server":
								state["serveragent"] = value.strip()
					elif self.protocol in ProbeServer.PROTOCOL_DIRECT_TLS:
						# Check email servers
						if self.protocol == ProbeServer.PROTOCOL_IMAP_S:
							agent = MailTest.do_imap_start(connection, False, debug=self.debug)
						elif self.protocol == ProbeServer.PROTOCOL_SMTP_S:
							agent = MailTest.do_smtp_start(connection, False, debug=self.debug)
						elif self.protocol == ProbeServer.PROTOCOL_POP_S:
							agent = MailTest.do_pop_start(connection, False, debug=self.debug)
						state["serveragent"] = agent
			except socket.error:
				if not mode or not mode.get("trigger_renegotiation", False):
					raise
				
			# Check if client certificates, renegotiation were requested
			state["clientcert_req"] = connection.clientcertificate_requested
			if not state.get("renegotiate_triggered", False):
				state["renegotiate_triggered"]= connection.renegotiationStarted
			if connection.renegotiationStarted and connection._handshake_in_progress:
				raise TLSAbruptCloseError("Renegotiation Failed")
			connection.close()
		except socket.error, error:
			if self.debug:
				print  self.servername, ":", self.port, ": Negotiation Failed socket error: ", error.message, "\n"
			if mode:
				mode["socket-error"] = str(error)
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version
				state["clientcert_req"] = connection.clientcertificate_requested
				state["renegotiate_triggered"]= connection.renegotiationStarted
			connection.close()
			connection = None
			return False
		except TLSAbruptCloseError, abrupt_error:
			if self.debug:
				print self.servername, ":", self.port, ": Negotiation Failed Connection closed error: ", abrupt_error, "\n"
			if mode:
				mode["abrubt-error"] = str(abrupt_error)
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version
				state["clientcert_req"] = connection.clientcertificate_requested
				state["renegotiate_triggered"]= connection.renegotiationStarted
			connection.close()
			connection = None
			return False
		except TLSAuthenticationError, tlsa_error:
			if self.debug:
				print self.servername, ":", self.port, ": Negotiation Failed Authentication error: ", tlsa_error, "\n"
			if mode:
				mode["tls-auth-error"] = str(tlsa_error)
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version
				state["clientcert_req"] = connection.clientcertificate_requested
			connection.close()
			connection = None
			return False
		except TLSLocalAlert, tls_error:
			if self.debug:
				print self.servername, ":", self.port, ": Negotiation Failed Local TLS error: ", tls_error, "\n"
			if mode:
				mode["tls-local-error"] = str(tls_error)
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version
				state["clientcert_req"] = connection.clientcertificate_requested
				state["renegotiate_triggered"]= connection.renegotiationStarted
			if settings.start_fake_renego_indication and tls_error.description == AlertDescription.handshake_failure + 2048:
				state["accepted_fake_renego"] = True
			connection.close()
			connection = None
			return False
		except TLSRemoteAlert, tls_error:
			if self.debug:
				print self.servername, ":", self.port, ": Negotiation Failed Remote TLS error: ", tls_error, "\n"
			if mode:
				mode["tls-remote-error"] = str(tls_error)
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version
				state["clientcert_req"] = connection.clientcertificate_requested
				state["renegotiate_triggered"]= connection.renegotiationStarted
			connection.close()
			connection = None
			return False
		except TLSAlert, tls_error:
			if self.debug:
				print self.servername, ":", self.port, ": Negotiation Failed TLS error: ", tls_error, "\n"
			if mode:
				mode["tls-error"] = str(tls_error)
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version
				state["clientcert_req"] = connection.clientcertificate_requested
				state["renegotiate_triggered"]= connection.renegotiationStarted
			connection.close()
			connection = None
			return False
		except BaseException, error:
			if self.debug:
				print self.servername, ":", self.port, ": Negotiation Failed Unknown error\n"
			if mode:
				mode["unknown-error"] = str(error)
				if "partial_record" in mode:
					raise
			if connection.detected_version > (0,0):
				state["detected_version"] = connection.detected_version
				state["clientcert_req"] = connection.clientcertificate_requested
				state["renegotiate_triggered"]= connection.renegotiationStarted
			connection.close()
			connection = None
			if settings.just_test_cipher:
				raise
			return False
		except:
			raise
			

		return True;
	
	def Probe(self, do_full_test=False):
		"""
		Run through the whole testsuite; do_full_test means to 
		perform tests of capabilities, such as extensions that 
		we have already tested
		
		Tests are selected by enabling various protocol features 
		and instrumentation in the TLS implementation library
		"""

		failed_any = False
		connected = False

		extensions_tolerated = False

		last_ver = (0,0)
		
		# Loop through various TLS features
		#
		# Versions: varying both the record protocol version and the advertised version
		# Some undefined versions are included to test version tolerance
		#
		# Extensions: enabled or not
		#
		# Using incorrect versions in the RSA Client Key Exchange: enabled or not
		for version, version_rec in [((3,0),(0,0)), ((3,1),(0,0)), ((3,1),(3,1)),   ((3,2),(0,0)), ((3,2),(3,1)), ((3,3),(0,0)), ((3,3),(3,1)), ((3,4),(0,0)), 
					#((3,11),(0,0)), 
					((4,1),(0,0))]:
			if version_rec != (0,0):
				if version in self.supported_versions and any([True for x in self.passed_modes if x["version"] == version and x["extensions"]==False and  x["bad_version"]==False]):
					continue				
				else:
					for x1 in [x for x in self.failed_modes if x["version"] == version]:
						del self.failed_modes_short[self.failed_modes_short.index(x1["text"])]
						del self.failed_modes[self.failed_modes.index(x1)]
					for x1 in [x for x in self.non_compliant_modes if x["version"] == version]:
						del self.non_compliant_modes_short[self.non_compliant_modes_short.index(x1["text"])]
						del self.non_compliant_modes[self.non_compliant_modes.index(x1)]
					for x1 in [x for x in self.passed_modes if x["version"] == version]:
						del self.passed_modes_short[self.passed_modes_short.index(x1["text"])]
						del self.passed_modes[self.passed_modes.index(x1)]
			elif self.detected_ch_rec_sameversion:
				version_rec = (3,1)
			for extensions_enabled in ([False, True] + (ProbeServer.EXTENSION_SET_LIST_CHECKED if not self.tested_specific_intolerance and version >= (3,1) and max(self.supported_versions + [(0,0)]) >= (3,1) else [])):
				for incorrect_version_enabled in [False, True]:
					if incorrect_version_enabled and version <= (3,0):
						continue;
					if incorrect_version_enabled and version == last_ver:
						continue;
					if incorrect_version_enabled and extensions_enabled:
						continue;
					if extensions_enabled and not do_full_test and not isinstance(extensions_enabled, list) and (extensions_tolerated or version > (3,1)) :
						continue;
					if isinstance(extensions_enabled, list):
						if version < (3,1):
							continue
						if extensions_tolerated:
							continue
						self.tested_specific_intolerance =True
					
					should_fail = incorrect_version_enabled;
					connected_version = None
	
					mode_description = "Version %d.%d" % (version[0], version[1])
					if extensions_enabled:
						mode_description += " with Extensions"
					else: 
						mode_description += " without Extensions" 
						
					if incorrect_version_enabled:
						mode_description += " with incorrect client key exchange version"
					
					tested_num = 0;
					test_finished = False;
					while not test_finished and tested_num < self.maxtest_iterations:
						tested_num += 1 

						#register which case is being tested
						mode = {"version":version, 
								"extensions":extensions_enabled,
								"bad_version":incorrect_version_enabled,
								"version_rec": version_rec,
								"text":mode_description}
						if self.debug:
							print mode_description, "\n"
						
						#set settings for connection
						settings = HandshakeSettings()
						settings.maxVersion = version
						settings.send_extensions = extensions_enabled
						settings.premaster_version_correct = not incorrect_version_enabled
						settings.send_renego_extensions= True
						settings.use_no_cert_alert = self.use_no_cert_alert_fallback
						if version_rec > (0,0):
							settings.record_versions = version_rec
						state={}
	
						# Perform test
						if self.__DoConnection(settings, mode, state):
							# If connection established, check properties of connection
							
							connected_version = state["version"]
							if last_ver < connected_version:
								last_ver = connected_version
							if connected_version == version:
								should_fail = False
								if version_rec > (0,0):
									self.detected_ch_rec_sameversion =True
							mode["negotiated_version"]=connected_version
							self.have_renego = self.have_renego or state["renego_supported"]
							if self.have_renego and not state["renego_supported"]:
								self.renego_unstable = True
							self.have_SNI = self.have_SNI or state["SNI_support"]
							self.sent_SNI_Alert = self.sent_SNI_Alert or state["SNI_alert"]
							if not self.certificate_status: 
								self.certificate_status = state["certificate_status"]
							if not self.clientcertificate_requested:
								self.clientcertificate_requested = state["clientcert_req"]
							if state["clientcert_req"] and self.use_no_cert_alert_fallback:
								self.used_no_cert_alert_fallback = True 
							if not self.requested_renegotiation:
								self.requested_renegotiation = state.get("renegotiate_triggered", False)
							session = state["session"]
							if session and not self.sent_session_ticket:
								self.sent_session_ticket = (session.session_ticket != None)
							
							test_finished = True
							if should_fail:
								# Ooops! The server should not have accepted this connection
								failed_any = True
								self.failed_modes.append(mode)
								self.failed_modes_short.append(mode["text"])
								self.non_compliant = True
								self.non_compliant_modes.append(mode)
								self.non_compliant_modes_short.append(mode["text"])
							else:
								# register more information about successfully established connections
								if state["selected_cipher"] and constants.CipherSuite.toText[state["selected_cipher"]] not in self.ciphers_supported:
									self.ciphers_supported.append(constants.CipherSuite.toText[state["selected_cipher"]])
								self.passed_any = True
								if  True: #not isinstance(extensions_enabled, list):
									self.passed_modes.append(mode)
									self.passed_modes_short.append(mode["text"])
									if not incorrect_version_enabled:
										if version not in self.version_tolerated:
											self.version_tolerated.append(version)
										if extensions_enabled and version not in self.extension_tolerated:
											self.extension_tolerated.append(version)
								connected =True
								if not self.certificates:
									#register the certificate chain
									self.certificates = {
										"certificate_list": [{
											"common-name":x.getCommonName(),
											"finger-print":x.getFingerprint(sha256.sha256),
											"binary certificate": x.bytes
															 } for x in state["cert"]],
										"raw_certificate":state["raw_certificate"]
										}
								
								if connected_version not in self.supported_versions :
									self.supported_versions.append(connected_version)
								if extensions_enabled == True and connected_version > (3,0):
									extensions_tolerated = True
									
								
							if self.debug:
								print "\tAccessed\n"
						else:
							# Connection faile
							if not self.requested_renegotiation:
								self.requested_renegotiation = state.get("renegotiate_triggered", False)
							if should_fail:
								# This should fail, so the test is successful
								self.passed_any = True
								self.passed_modes.append(mode)
								self.passed_modes_short.append(mode["text"])
							else:
								# Ooops! The server failed to establish a connection, when it should have accepted it 
								if "detected_version" in state:
									det_ver = state["detected_version"]
									mode["detected_version"]= det_ver
									if det_ver not in self.detected_versions :
										self.detected_versions.append(det_ver)
									if state["clientcert_req"]: 
										if not self.clientcertificate_requested:
											self.clientcertificate_requested = True
										if det_ver >= (3,1)  and not extensions_enabled and not incorrect_version_enabled:
											if not self.use_no_cert_alert_fallback :
												self.use_no_cert_alert_fallback = True
												continue
											else:
												self.use_no_cert_alert_fallback = False
												
										self.clientcertificate_required = True
										# Assume this actually (almost) succeeded, but was blocked by a missing client certificate 
										if det_ver >= (3,0) and det_ver<= (3,3) and not extensions_enabled and not incorrect_version_enabled:
											self.passed_modes.append(mode)
											self.passed_modes_short.append(mode["text"])
											test_finished = True
											continue;
									elif det_ver >= (3,0) and det_ver<= (3,3) and self.supported_versions and not extensions_enabled and not incorrect_version_enabled:
										# Assume this actually (almost) succeeded, but was blocked for some reason 
										self.passed_modes.append(mode)
										self.passed_modes_short.append(mode["text"])
										test_finished = True
										continue;


								if tested_num < self.maxtest_iterations:
									continue

								failed_any = True
								if not isinstance(extensions_enabled, list):
									self.failed_modes.append(mode)
									self.failed_modes_short.append(mode["text"])
								if self.protocol == ProbeServer.PROTOCOL_HTTPS and  version == (3,0) and not extensions_enabled and not incorrect_version_enabled:
									# if we failed the very first connection using basic SSL v3 failed, test for SSL v2 support, then exit. No need to perform more tests
									self.available = False
									self.not_available = True
									test_sslv2 = True
									# Test ssl v2
									
									settings = HandshakeSettings()
									settings.maxVersion = (3,0)
									if SSLv2Test.TestConnectionV2(self, settings):
										self.available = True
										self.not_available = False
							
									settings = HandshakeSettings()
									settings.maxVersion = (0,2)
									if SSLv2Test.TestConnectionV2(self, settings):
										self.available = True
										self.not_available = False

									return; # Could not connect using SSL v3, probably offline or timed out, no need to check.
								elif self.protocol != ProbeServer.PROTOCOL_HTTPS and  version == (3,1) and not extensions_enabled and not incorrect_version_enabled:
									# For non-HTTPS servers, TLS 1.0 is the first, and SSL v2 is not supposed to be supported 
									self.available = False
									self.not_available = True
									return; # Could not connect using TLS 1, probably offline or timed out, no need to check.
								if extensions_enabled:
									if version == (3,0):
										self.extension_intolerant_v3 = True
									elif isinstance(extensions_enabled, list):
										self.intolerant_for_extension.append(extensions_enabled)
									else:
										self.extension_intolerant = True;
										self.extension_intolerant_v3 = False
								self.non_compliant = True
								if not isinstance(extensions_enabled, list):
									self.non_compliant_modes.append(mode)
									self.non_compliant_modes_short.append(mode["text"])

							test_finished = True


		# if the server is available and allows connection, perform more tests
		if self.available and self.passed_any and connected:
			# Establish default connection parameters, highest version, best extensions
			version_ext_list = [(x["extensions"],x["version"] ) for x in self.passed_modes if not x["bad_version"] and x["version"] <=(3,3)]
			version_ext_list = [(e,v) for e, v in version_ext_list if e == max([e1 for e1,v1 in version_ext_list if v1 == v])]
			passed_extension, passed_version = max(version_ext_list)
			if passed_extension and passed_version > (3,0) and min([(256, 0)]+[v for e, v in version_ext_list if not e and v>(3,0)]) < passed_version:
				self.reversed_extension_intolerance = True;
				passed_extension, passed_version = max([(e,v) for e,v in version_ext_list if not e])
			tolerated_version = max(self.extension_tolerated if passed_extension else self.version_tolerated)

			# Test record protocol/client hello version swap
			settings = HandshakeSettings()
			settings.maxVersion = (3,1)
			settings.send_extensions = not self.extension_intolerant
			settings.premaster_version_correct = True
			settings.send_renego_extensions= True
			settings.send_swapped_hello_versions = True
			state = {}
			if self.__DoConnection(settings, None, state):
				if state["version"] > (3,0):
					self.detected_ch_version_swap = True
			if not self.requested_renegotiation:
				self.requested_renegotiation = state.get("renegotiate_triggered", False)

			# Test session resume capabilities
			settings = HandshakeSettings()
			settings.maxVersion = passed_version
			settings.send_extensions = passed_extension
			if settings.send_extensions:
				settings.send_extensions = list(constants.IndividualExtensionsTested.ALL).remove(constants.IndividualExtensionsTested.SESSIONTICKET)  
			settings.premaster_version_correct = True
			settings.send_renego_extensions= True
			state = {}
			self.tested_session =True
			
			if self.__DoConnection(settings, None, state):
				session = state["session"]
				negotiated_version = state["version"]
				if not self.requested_renegotiation:
					self.requested_renegotiation = state.get("renegotiate_triggered", False)
				if session and session.valid() and session.resumable:
					self.resumable_session = True
					settings = HandshakeSettings()
					settings.maxVersion = negotiated_version
					settings.send_extensions = passed_extension
					if settings.send_extensions:
						settings.send_extensions = list(constants.IndividualExtensionsTested.ALL).remove(constants.IndividualExtensionsTested.SESSIONTICKET)  
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					state = {}
					if self.__DoConnection(settings, None, state, session=session):
						session_resume_same_version = state["session"]
						if session_resume_same_version == session:
							self.resumed_session =True

					if not self.requested_renegotiation:
						self.requested_renegotiation = state.get("renegotiate_triggered", False)

				# Which version is selected
				if self.resumed_session and passed_version>negotiated_version:
					settings = HandshakeSettings()
					settings.maxVersion = passed_version
					settings.send_extensions = passed_extension
					if settings.send_extensions:
						settings.send_extensions = list(constants.IndividualExtensionsTested.ALL).remove(constants.IndividualExtensionsTested.SESSIONTICKET)  
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					state = {}
					if self.__DoConnection(settings, None, state, session=session):
						session_resume_same_version1 = state["session"]
						if session_resume_same_version1 == session:
							self.resumed_session_with_original =True
						else:
							self.new_session_with_original = True
					else:
						self.fail_resumed_session_with_original=True

					if not self.requested_renegotiation:
						self.requested_renegotiation = state.get("renegotiate_triggered", False)

			if self.sent_session_ticket:
				#if we tested session ticket extension earlier, try it to see if the server supports it, and if it resumes
				settings = HandshakeSettings()
				settings.maxVersion = passed_version
				settings.send_extensions = passed_extension
				settings.premaster_version_correct = True
				settings.send_renego_extensions= True
				state = {}
				self.tested_session =True
				if self.__DoConnection(settings, None, state):
					session = state["session"]
					negotiated_version = state["version"]
					if not self.requested_renegotiation:
						self.requested_renegotiation = state.get("renegotiate_triggered", False)
					if session and session.valid() and session.resumable and session.session_ticket != None:
						settings = HandshakeSettings()
						settings.maxVersion = negotiated_version
						settings.send_extensions = passed_extension
						settings.premaster_version_correct = True
						settings.send_renego_extensions= True
						state = {}
						if self.__DoConnection(settings, None, state, session=session):
							session_resume_same_version = state["session"]
							if session_resume_same_version == session:
								self.resumed_session_ticket =True
	
						if not self.requested_renegotiation:
							self.requested_renegotiation = state.get("renegotiate_triggered", False)

			if self.have_renego:
				#if server had renego patch support, check if the protection actually works, by using bogus renego indictions 
				for i in range(10):
					settings = HandshakeSettings()
					settings.maxVersion = passed_version
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.start_fake_renego_indication=True
					mode = {}
					state={}
					if self.__DoConnection(settings, mode, state):
						if not state.get("renego_supported", False):
							continue 
						self.accepted_start_fake_renego = True 
					elif state.get("accepted_fake_renego", False):
						if not state.get("renego_supported", False):
							continue 
						self.accepted_start_fake_renego =True
					else:
						self.accepted_start_fake_renego = False
					break;

				# Check if the server accepts both the Renego extension and the Renego SCSV at the same time
				self.accepted_renego_ext_and_scsv = False
				for i in range(10):
					settings = HandshakeSettings()
					settings.maxVersion = passed_version
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.send_renego_extension_and_scsv=True
					mode = {}
					state={}
					if self.__DoConnection(settings, mode, state):
						if not state.get("renego_supported", False):
							continue 
						self.accepted_renego_ext_and_scsv = True
					elif i < 2:
						continue
					else:
						self.accepted_renego_ext_and_scsv = False
					break;


			check_server_worked = None
			use_opera = False
			if self.protocol in ProbeServer.PROTOCOL_DIRECT_TLS:
				# If the server accepts direct TLS connections (not STARTTLS) check what the server is (server agent)
				while True:						
					settings = HandshakeSettings()
					settings.maxVersion = passed_version
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					mode = {"check-server":True}
					state={}

					if self.__DoConnection(settings, mode, state):
						check_server_worked = state.get("response",0)
						self.server_agent = state.get("serveragent",None)
						if self.server_agent and len(self.server_agent) > 300:
							self.server_agent =self.server_agent[:300]
					elif state.get("renegotiate_triggered", False) and  state.get("clientcert_req", False):
							if self.use_no_cert_alert_fallback:
								self.used_no_cert_alert_fallback = True 
							else:
								self.use_no_cert_alert_fallback =True
								continue
					
					if not self.clientcertificate_requested:
						self.clientcertificate_requested = state.get("clientcert_req",False)
					if not self.requested_renegotiation:
						self.requested_renegotiation = state.get("renegotiate_triggered", False)

					break;

				if not check_server_worked:
					# If the test did not work, try using Opera as the User agent, instead of the TLS Prober string
					while True:						
						settings = HandshakeSettings()
						settings.maxVersion = passed_version
						settings.send_extensions = passed_extension
						settings.premaster_version_correct = True
						settings.send_renego_extensions= True
						settings.use_no_cert_alert = self.use_no_cert_alert_fallback
						mode = {"check-server":True, "opera":True}
						state={}

						if self.__DoConnection(settings, mode, state):
							check_server_worked = state.get("response",0)
							use_opera = True
							self.server_agent = state.get("serveragent",None)
							if self.server_agent and len(self.server_agent) > 300:
								self.server_agent =self.server_agent[:300]
						elif state.get("renegotiate_triggered", False) and  state.get("clientcert_req", False):
								if self.use_no_cert_alert_fallback:
									self.used_no_cert_alert_fallback = True 
								else:
									self.use_no_cert_alert_fallback =True
									continue
						
						if not self.clientcertificate_requested:
							self.clientcertificate_requested = state["clientcert_req"]
						if not self.requested_renegotiation:
							self.requested_renegotiation = state.get("renegotiate_triggered", False)
	
						break;
					

			# Check if server tolerates extra record padding in block cipher encrypted connection
			settings = HandshakeSettings()
			settings.maxVersion = passed_version
			settings.send_extensions = passed_extension
			settings.premaster_version_correct = True
			settings.send_renego_extensions= True
			settings.extra_padding_bytes = 64
			settings.use_no_cert_alert = self.use_no_cert_alert_fallback
			settings.ciphersuites =[x for x in constants.CipherSuite.blockCipherSuites if constants.CipherSuite.toText[x] in self.ciphers_supported]
			if  settings.ciphersuites:
				mode = {"check-server":True, "opera":use_opera}
				state={}
				if not self.__DoConnection(settings, mode, state):
					self.extra_padding_problems = True
					
			if passed_extension:
				# Test if the server tolerates Client Hello's that are 256 bytes or longer 
				failed = False
				for (v, f) in [
						((3,0), RESULTC_CH_MINLEN_FAILED_256_30),
						((3,1), RESULTC_CH_MINLEN_FAILED_256_31),
						((3,3), RESULTC_CH_MINLEN_FAILED_256_33),
								]:
					if v>passed_version:
						continue
					settings = HandshakeSettings()
					settings.maxVersion = passed_version
					settings.send_extensions = True
					#settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					#settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					settings.extra_action_dict = {TestHandshake.EXTRA_CH_MIN_LEN:256}
					settings.record_versions=v
					mode = {"check-server":True,
						"opera":use_opera,
						}
					state={}
					if not self.__DoConnection(settings, mode, state):
						self.test_results.add(RESULTC_CH_MINLEN_FAILED_256)
						self.test_results.add(f)
						failed = True
					if not self.requested_renegotiation:
						self.requested_renegotiation = state.get("renegotiate_triggered", False)
				if not failed:
					self.test_results.add(RESULTC_CH_MINLEN_PASSED_256)
			else:
				self.test_results.add(RESULTC_CH_MINLEN_NOT_TESTED)

			# Test server with a record protocol version higher than supported; presently testing only TLS 1.1 and TLS 1.2
			did_test = False
			failed = False
			for v, f,p in [((3,2), RESULTC_RECV_32_FAILED, RESULTC_RECV_32_PASSED), ((3,3), RESULTC_RECV_33_FAILED, RESULTC_RECV_33_PASSED)]:
				if v in self.supported_versions:
					continue

				if [x for x in self.passed_modes if x["version"] == v and x["bad_version"] == False]:
					did_test = True
					settings = HandshakeSettings()
					settings.maxVersion = v
					settings.send_extensions = any([x for x in self.passed_modes if x["version"] == v and x["bad_version"] == False and x["extensions"] == True]) 
					#settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					#settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					settings.record_versions=v
					mode = {}
					state={}
					if not self.__DoConnection(settings, mode, state):
						self.test_results.add(RESULTC_RECV_ANY_FAILED)
						self.test_results.add(f)
						failed = True
					else:
						self.test_results.add(p)
						
					if not self.requested_renegotiation:
						self.requested_renegotiation = state.get("renegotiate_triggered", False)
			if did_test:
				self.test_results.add(RESULTC_HIGHER_RECV_TEST)
				if not failed:
					self.test_results.add(RESULTC_RECV_ANY_PASSED)
			else:	
				self.test_results.add(RESULTC_HIGHER_RECV_NOTEST)
					

			if not self.requested_renegotiation:
				# If the server did not trigger renegotiation, attempt to trigger it ourselves 
				settings = HandshakeSettings()
				settings.maxVersion = passed_version
				settings.send_extensions = passed_extension
				settings.premaster_version_correct = True
				settings.send_renego_extensions= True
				settings.use_no_cert_alert = self.use_no_cert_alert_fallback
				mode = {"check-server":True,
						"opera":use_opera,
						"trigger_renegotiation":True}
				state={}
				if self.__DoConnection(settings, mode, state):
					self.accepted_renegotiation =True
					
				else:
					self.accepted_renegotiation =False
			else:
				# Otherwise do a request and see if the renegotiation completes
				settings = HandshakeSettings()
				settings.maxVersion = passed_version
				settings.send_extensions = not passed_extension
				settings.premaster_version_correct = True
				settings.send_renego_extensions= True
				settings.use_no_cert_alert = self.use_no_cert_alert_fallback
				settings.refuse_renegotiation=True
				mode = {"check-server":True, "opera":use_opera}	
				state={}
				if self.__DoConnection(settings, mode, state):
					if state.get("renegotiate_triggered", False):
						self.completed_renegotiation =True
				elif state.get("renegotiate_triggered", False):
					self.completed_renegotiation =False

			#
			if (self.accepted_renegotiation or self.requested_renegotiation) and self.have_renego:
				for i in range(10):
					settings = HandshakeSettings()
					settings.maxVersion = passed_version
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.use_fake_renego_indication=True
					settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					mode = {"check-server":True,
							"opera":use_opera,
							"trigger_renegotiation":self.accepted_renegotiation}
					state={}
					if self.__DoConnection(settings, mode, state):
						if not state.get("renego_supported", False):
							continue 
						self.accepted_renegotiation_fake_renego = (state.get("renegotiate_triggered", False) or self.accepted_renegotiation) 
					elif state.get("renegotiate_triggered", False) or self.accepted_renegotiation:
						if not state.get("renego_supported", False):
							continue 
						self.accepted_renegotiation_fake_renego =False
					break;

			if self.accepted_renegotiation or self.requested_renegotiation: 
				
				if tolerated_version >  max(self.supported_versions):
					settings = HandshakeSettings()
					settings.maxVersion = tolerated_version
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.renegotiation_settings = HandshakeSettings()
					settings.renegotiation_settings.maxVersion = settings.maxVersion
					settings.renegotiation_settings.force_premaster_version = tolerated_version
					settings.renegotiation_settings.send_extensions = passed_extension
					settings.renegotiation_settings.send_renego_extensions= True
					settings.renegotiation_settings.renegotiation_new_session = True
					settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					
					mode = {"check-server":True,
							"opera":use_opera,
							"trigger_renegotiation":self.accepted_renegotiation}
					state={}
					if self.__DoConnection(settings, mode, state):
						self.accepted_renegotiation_higher_premaster =True
					else:
						self.accepted_renegotiation_higher_premaster =False

					settings = HandshakeSettings()
					settings.maxVersion = tolerated_version
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.renegotiation_settings = HandshakeSettings()
					settings.renegotiation_settings.maxVersion = settings.maxVersion
					settings.renegotiation_settings.force_premaster_version = (tolerated_version[0], tolerated_version[1]+1)
					settings.renegotiation_settings.send_extensions = passed_extension
					settings.renegotiation_settings.send_renego_extensions= True
					settings.renegotiation_settings.renegotiation_new_session = True
					settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					
					mode = {"check-server":True,
							"opera":use_opera,
							"trigger_renegotiation":self.accepted_renegotiation}
					state={}
					if self.__DoConnection(settings, mode, state):
						self.accepted_renegotiation_even_higher_premaster =True
					else:
						self.accepted_renegotiation_even_higher_premaster =False

		self.Do_Ciphertest()

		# Test false-start if RSA and key-security > 128 bit
		if (self.available and self.passed_any and connected and
			check_server_worked and 
			self.protocol in [ProbeServer.PROTOCOL_HTTPS] and
			set([constants.CipherSuite.toText[x] for x in [ 
				constants.CipherSuite.TLS_RSA_WITH_RC4_128_MD5, 
				constants.CipherSuite.TLS_RSA_WITH_RC4_128_SHA, 
				constants.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, 
				constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
				constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, 
				constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, 
				constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256]]) & set(self.ciphers_supported)):

			checked_before = False
			failed = False
			while True:
				settings = HandshakeSettings()
				settings.maxVersion = passed_version
				settings.send_extensions = passed_extension
				settings.premaster_version_correct = True
				settings.send_renego_extensions= True
				settings.use_no_cert_alert = self.use_no_cert_alert_fallback
				settings.ciphersuites = [
						constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
						constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, 
						constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, 
						constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
						constants.CipherSuite.TLS_RSA_WITH_RC4_128_MD5, 
						constants.CipherSuite.TLS_RSA_WITH_RC4_128_SHA, 
						constants.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, 
					]
				mode = {"check-server":True,
						"opera":use_opera,
						"version_rec": ( (3,0) if passed_version == (3,0) else (3,1)),
						"false-start":True
					}
				state={}

				if self.__DoConnection(settings, mode, state):
					resp = state.get("response",0)
					if resp and ((resp > 0 and resp<400) or resp == check_server_worked):
						if self.debug:
							print "OK", resp
						self.accept_false_start = True
					else:
						if not checked_before:
							checked_before =True
							continue
						if self.debug:
							print "Failed" , state, mode
						failed = True
				else:
					if not checked_before:
						checked_before =True
						continue
					if self.debug:
						print "Failed", state, mode
					failed = True
				break

			if failed:
				checked_before = False
				while True:
					settings = HandshakeSettings()
					settings.maxVersion = passed_version
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					mode = {"check-server":True, "opera":use_opera
						}
					state={}
					if self.__DoConnection(settings, mode, state):
						resp = state.get("response",0)
						if resp and ((resp > 0 and resp<400) or resp == check_server_worked):
							self.accept_false_start = False
						else:
							if not checked_before:
								checked_before =True
								continue
							self.accept_false_start = None # We can't get a successful connection, suspect server is offline
					else:
						if not checked_before:
							checked_before =True
							continue
						self.accept_false_start = None # We can't get a successful connection, suspect server is offline
					break
			
		#test with partial or empty records before payload to check if a BEAST CBC workaround will work properly
		if (self.available and self.passed_any and connected and
			check_server_worked and 
			self.protocol in ProbeServer.PROTOCOL_DIRECT_TLS and
			set([constants.CipherSuite.toText[x] for x in [constants.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, 
				constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
				constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, 
				constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, 
				constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256]]) & set(self.ciphers_supported)):

			self.working_part_record = []
			for part_len in [0,1,2,-1,-2]:

				checked_before = False
				while True:						
					settings = HandshakeSettings()
					settings.maxVersion = (passed_version if passed_version<= (3,1) else (3,1))
					settings.send_extensions = passed_extension
					settings.premaster_version_correct = True
					settings.send_renego_extensions= True
					settings.use_no_cert_alert = self.use_no_cert_alert_fallback
					settings.ciphersuites = [
							constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
							constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, 
							constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, 
							constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
							constants.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, 
						]
					mode = {"check-server":True,
						"opera":use_opera,
						"partial_record":part_len
						}
					state={}

					if self.__DoConnection(settings, mode, state):
						resp = state.get("response",0)
						if resp and ((resp > 0 and resp<400) or resp == check_server_worked):
							if self.debug:
								print "OK", part_len, resp
							self.working_part_record.append(part_len)
						else:
							if not checked_before:
								checked_before =True
								continue
							if self.debug:
								print "Failed", part_len#, state, mode
					else:
						if not checked_before:
							checked_before =True
							continue
						if self.debug:
							print "Failed", part_len#, state, mode
					break;

			#test with partial or empty records before payload to check if a BEAST CBC workaround will work properly; collect records into single network send
			if self.working_part_record != [0,1,2,-1,-2]:
				self.working_part_record_collect = []
				for part_len in [0,1,2,-1,-2]:
					checked_before = False
					while True:						
						settings = HandshakeSettings()
						settings.maxVersion = (passed_version if passed_version<= (3,1) else (3,1))
						settings.send_extensions = passed_extension
						settings.premaster_version_correct = True
						settings.send_renego_extensions= True
						settings.use_no_cert_alert = self.use_no_cert_alert_fallback
						settings.ciphersuites = [
								constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
								constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, 
								constants.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, 
								constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
								constants.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, 
							]
						mode = {"check-server":True,
							"opera":use_opera,
							"partial_record":part_len,
							"partial_record_collect":True
							}
						state={}

						if self.__DoConnection(settings, mode, state):
							resp = state.get("response",0)
							if resp and ((resp > 0 and resp<400) or resp == check_server_worked):
								print "OK", part_len, resp
								self.working_part_record_collect.append(part_len)
							else:
								if not checked_before:
									checked_before =True
									continue
								if self.debug:
									print "Failed", part_len#, state, mode
						else:
							if not checked_before:
								checked_before =True
								continue
							if self.debug:
								print "Failed", part_len#, state, mode

						break;
					
		self.passed_all = not failed_any
		if self.debug:
			print "tests completed\n"

	def Do_Ciphertest(self):
		"""Test various cipher suite capabilties, as a smoke test""" 
		
		versions = self.supported_versions if self.supported_versions else self.detected_versions
		for use_version in [max(versions if versions else [(3,1)])] + ([(3,x) for x in range(0,max(versions)[1])] if max(versions) > (3,0) else []):
			for single_cipher in [x for x in constants.CipherSuite.rsaSuites if constants.CipherSuite.toText[x] not in self.ciphers_supported]:
				if self.debug:
					print "Testing single cipher %04x" % (single_cipher) 

				settings = HandshakeSettings()
				settings.maxVersion = use_version
				settings.send_extensions = not self.extension_intolerant
				settings.premaster_version_correct = True
				settings.send_renego_extensions= True
				settings.ciphersuites = [single_cipher]
				settings.record_versions = settings.maxVersion
				state = {}

				if self.__DoConnection(settings, None, state):
					connected =True
					self.available = True
					if state["selected_cipher"] and constants.CipherSuite.toText[state["selected_cipher"]] not in self.ciphers_supported:
						self.ciphers_supported.append(constants.CipherSuite.toText[single_cipher])
					if (single_cipher in constants.CipherSuite.minimum_TLSversion and state["detected_version"] and 
						constants.CipherSuite.minimum_TLSversion[single_cipher] > state["detected_version"]):
						self.selected_cipher_later_version = True
					if (single_cipher in constants.CipherSuite.maximum_TLSversion and state["detected_version"] and
						constants.CipherSuite.maximum_TLSversion[single_cipher] < state["detected_version"]):
						self.selected_deprecated_cipher = True
					if self.debug:
						print "\tAccessed single cipher\n"

			for cipher_list in [constants.CipherSuite.likelyUnsupportedSuites, constants.CipherSuite.lessLikelyUnsupportedSuites, constants.CipherSuite.unlikelyUnsupportedSuites]:

				settings = HandshakeSettings()
				settings.just_test_cipher = True
				settings.maxVersion = use_version
				settings.send_extensions = not self.extension_intolerant
				settings.premaster_version_correct = True
				settings.send_renego_extensions= True
				settings.ciphersuites = [x for x in cipher_list if constants.CipherSuite.toText[x] not in self.ciphers_supported]
				settings.record_versions = settings.maxVersion
				state = {}

				if not settings.ciphersuites:
					continue;

				if self.__DoConnection(settings, None, state):
					connected =True
					self.available = True
					if state["selected_cipher"] and constants.CipherSuite.toText[state["selected_cipher"]] not in self.ciphers_supported:
						self.ciphers_supported.append(constants.CipherSuite.toText[state["selected_cipher"]]) 
					for single_cipher in [x for x in cipher_list if constants.CipherSuite.toText[x] not in self.ciphers_supported]:
						if self.debug:
							print "Testing single cipher %04x" % (single_cipher) 
		
						settings = HandshakeSettings()
						settings.just_test_cipher = True
						settings.maxVersion = use_version
						settings.send_extensions = not self.extension_intolerant
						settings.premaster_version_correct = True
						settings.send_renego_extensions= True
						settings.ciphersuites = [single_cipher]
						settings.record_versions = settings.maxVersion
						state = {}
		
						if self.__DoConnection(settings, None, state):
							if state["selected_cipher"] and constants.CipherSuite.toText[state["selected_cipher"]] not in self.ciphers_supported:
								self.ciphers_supported.append(constants.CipherSuite.toText[single_cipher])
							if single_cipher in constants.CipherSuite.weakSuites:
								self.support_weak_ciphers =True
							if (single_cipher in constants.CipherSuite.minimum_TLSversion and state["detected_version"] and 
								constants.CipherSuite.minimum_TLSversion[single_cipher] > state["detected_version"]):
								self.selected_cipher_later_version = True
							if (single_cipher in constants.CipherSuite.maximum_TLSversion and state["detected_version"] and
								constants.CipherSuite.maximum_TLSversion[single_cipher] < state["detected_version"]):
								self.selected_deprecated_cipher = True
							
							if "dhe_keysize" in state:
								dhe_keysize = state["dhe_keysize"]
								if dhe_keysize and (not self.dhe_keysize or self.dhe_keysize > dhe_keysize):
									self.dhe_keysize = dhe_keysize
							if "weak_dhe_keysize" in state:
								dhe_keysize = state["weak_dhe_keysize"]
								if dhe_keysize and (not self.weak_dhe_keysize or self.weak_dhe_keysize > dhe_keysize):
									self.weak_dhe_keysize = dhe_keysize
							if self.debug:
								print "\tAccessed single cipher\n"

		# Test ssl v2 support
		if self.supported_versions or self.detected_versions:
			settings = HandshakeSettings()
			settings.maxVersion = max(self.supported_versions if self.supported_versions else self.detected_versions)
			SSLv2Test.TestConnectionV2(self, settings)

		settings = HandshakeSettings()
		settings.maxVersion = (0,2)
		SSLv2Test.TestConnectionV2(self, settings)
