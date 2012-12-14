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


import re
import datetime
import socket

# Test various mail protocols by sending enough commands to start a TLS connection 
# and establish a connection in that protocol 

def __read_lines(sock,current_buffer=None, debug=False):
	"""Read linse from a connection. 
	Return tuple of lines and the unprocessed lines
	32 second timeout
	"""
	buffer = current_buffer
	if isinstance(buffer, (list, tuple)):
		buffer = " ".join(buffer)

	sock.settimeout(32.0) # some mailservers are slow to respond
	read_count = 0
	started = datetime.datetime.now()
	while (not buffer or "\n" not in buffer):
		read_count += 1
		if isinstance(sock, socket.SocketType):
			inbuffer = sock.recv(1024)
		else:
			inbuffer = sock.read(1024)
		buffer = buffer + inbuffer if buffer else inbuffer
		if (datetime.datetime.now() - started).seconds >=32:
			raise socket.error("Timeout")		
	if debug:
		print "Received:", buffer
	
	lines = buffer.splitlines(True)
	buffer = None
	if "\n" not in lines[-1]:
		buffer = lines.pop(-1)
	if debug:
		print "lines:", lines

	# return to 10 second timeout
	sock.settimeout(10.0)
	
	return (lines, buffer)

def __read_imap_lines(sock,current_buffer=None, debug=False):
	"""Read IMAP protocol lines"""
	(lines, buffer) =  __read_lines(sock, current_buffer, debug)

	return  ([line.split(None,2) for line in lines], buffer)
	
def do_imap_start(sock, send_start_tls, debug=False):
	"""Start an IMAP connection"""
	buffer = None
	first_line = None
	handled_response = False
	started = datetime.datetime.now()
	while not handled_response:
		(lines, buffer) =  __read_imap_lines(sock, buffer, debug)
		
		if not first_line:
			first_line = lines[0]
		
		if not buffer:
			handled_response = True
		elif (datetime.datetime.now() - started).seconds >=32:
			raise socket.error("Timeout")	
		
	
	if len(first_line) != 3 or first_line[0:2] != ["*", 'OK'] :
		raise Exception("Bad server")
	
	first_line = first_line[2] #remove "* OK" prefix
	if first_line[0] == "[":
		first_line = first_line.partition("]")[2].strip() #strip leading capability segment
	if not first_line:
		first_line= "N/A"
	
	if send_start_tls:
		sock.send("A001 STARTTLS\n")
		
		handled_response = False
		started = datetime.datetime.now()
		while not handled_response:
			(lines, buffer) =  __read_imap_lines(sock, buffer, debug)
			
			for line in lines:
				if line[0] == "A001":
					if line[1] != "OK":
						raise Exception("Server does not support STARTTLS")
					handled_response = True
				elif handled_response:
					raise Exception("Server sent data after STARTTLS OK")
			if not handled_response and (datetime.datetime.now() - started).seconds >=32:
				raise socket.error("Timeout")		
		if buffer:
			raise Exception("Server sent data after STARTTLS OK")
					
		if debug:
			print "STARTTLS accepted"
	return first_line

def __split_smtp(line, debug=False):
	"""Split replies from SMTP servers"""
	split = re.search(r"^([0-9]+)([ -])(.*)$",line.rstrip())
	if split:
		if debug:
			print split.groups()
		return split.groups()
	return ("ERR", split,)

def __read_smtp_lines(sock,current_buffer=None, debug=False):
	"""read and parse SMTP replies"""
	(lines, buffer) =  __read_lines(sock, current_buffer, debug)

	return  ([__split_smtp(line, debug) for line in lines], buffer)
	

def do_smtp_start(sock, send_start_tls, debug=False):
	"""Start an SMTP connection"""
	buffer = None
	first_line = None
	started = datetime.datetime.now()
	handled_response = False
	while not handled_response:
		(lines, buffer) =  __read_smtp_lines(sock, buffer, debug)

		if not first_line:
			first_line = lines[0]
		
		if not buffer and any([line[1] == " " for line in lines]):
			handled_response = True
		if not handled_response and (datetime.datetime.now() - started).seconds >=32:
			raise socket.error("Timeout")		
	
	if len(first_line) != 3 or first_line[0] != "220" :
		raise Exception("Bad server")

	if first_line[1] == "-":
		first_line = first_line[2]
		while line in lines[1:]:
			if line[0] != "220":
				break;
			first_line += " " +line[2]
			if line[1] == " ":
				break;
	else:
		first_line = first_line[2] #remove "220" prefix
	
	components = first_line.split(None,4)
	components = components[0:min(len(components), 4)]
	if len(components)> 1:
		del components[0] #Hostname
		if len(components)> 1 and	components[0] in ["SMTP", "ESMTP"]:
			del components[0] #SMTP type
	
	if send_start_tls:
		sock.send("EHLO tlsprober.opera.com\n")
		
		started = datetime.datetime.now()
		handled_response = False
		while not handled_response:
			(lines, buffer) =  __read_smtp_lines(sock, buffer, debug)
			
			for line in lines:
				if len(line) != 3:
					raise Exception("Bad server")

				if line[0] == "250":
					if line[1] == " ":
						handled_response = True
				elif not handled_response:
					raise Exception("Error in response or not ESMTP server which would not support TLS")
				else:
					raise Exception("Server sent data after EHLO OK")
			if not handled_response and (datetime.datetime.now() - started).seconds >=32:
				raise socket.error("Timeout")		

		sock.send("STARTTLS\n")
		
		started = datetime.datetime.now()
		handled_response = False
		while not handled_response:
			(lines, buffer) =  __read_smtp_lines(sock, buffer, debug)
			
			for line in lines:
				if len(line) != 3:
					raise Exception("Bad server")

				if line[0] == "220":
					if line[1] == " ":
						handled_response = True
				elif not handled_response:
					raise Exception("No STARTTLS support")
				else:
					raise Exception("Server sent data after STARTTLS OK")
		
			if not handled_response and (datetime.datetime.now() - started).seconds >=32:
				raise socket.error("Timeout")		
		if buffer:
			raise Exception("Server sent data after STARTTLS OK")
					
		if debug:
			print "STARTTLS accepted"
	return first_line

def __read_pop_lines(sock,current_buffer=None, debug=False):
	"""Read and parse POP replies""" 
	(lines, buffer) =  __read_lines(sock, current_buffer, debug)

	return  ([line.split(None,1)	for line in lines], buffer)
	

def do_pop_start(sock, send_start_tls, debug=False):
	"""Start a POP connection"""
	buffer = None
	first_line = None
	started = datetime.datetime.now()
	handled_response = False
	while not handled_response:
		(lines, buffer) =  __read_pop_lines(sock, buffer, debug)

		if not first_line:
			first_line = lines[0]
		
		if not buffer:
			handled_response = True
		if not handled_response and (datetime.datetime.now() - started).seconds >=32:
			raise socket.error("Timeout")		
	
	if len(first_line) != 2 or first_line[0] != "+OK" :
		raise Exception("Bad server")
	
	first_line = first_line[1] #remove "220" prefix
	
	if send_start_tls:
		sock.send("STLS\n")
		
		started = datetime.datetime.now()
		handled_response = False
		while not handled_response:
			(lines, buffer) =  __read_pop_lines(sock, buffer, debug)
			
			for line in lines:
				if line[0] == "+OK":
					handled_response = True
				elif handled_response:
					raise Exception("Server sent data after STARTTLS OK")
			if not handled_response and (datetime.datetime.now() - started).seconds >=32:
				raise socket.error("Timeout")		
		
		if buffer:
			raise Exception("Server sent data after STARTTLS OK")
					
		if debug:
			print "STARTTLS accepted"
	return first_line
