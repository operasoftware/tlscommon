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

'''
Created on 31. mars 2012

@author: yngve
'''

# List of status codes used in both web prober and the batch prober 

RESULTC_CH_MINLEN_NOT_TESTED = "CMNT" # Client Hello Minimum length not tested
RESULTC_CH_MINLEN_PASSED_256 = "CMP1" # Client Hello Minimum length 256 passed
RESULTC_CH_MINLEN_FAILED_256 = "CMF1" # Client Hello Minimum length 256 failed
RESULTC_CH_MINLEN_FAILED_256_30 = "CM10" # Client Hello Minimum length 256 failed SSL v3
RESULTC_CH_MINLEN_FAILED_256_31 = "CM11" # Client Hello Minimum length 256 failed TLS 1.0
RESULTC_CH_MINLEN_FAILED_256_33 = "CM13" # Client Hello Minimum length 256 failed TLS 1.2

RESULTC_HIGHER_RECV_TEST = "HRVT" # Higher record versions than TLS 1.0 tested during handshake
RESULTC_HIGHER_RECV_NOTEST = "HRVN" # Higher record versions than TLS 1.0 not tested during handshake
RESULTC_RECV_ANY_FAILED = "HRAF" # Higher Record version tested during handshake, some failed
RESULTC_RECV_ANY_PASSED = "HRAP" # Higher Record version tested during handshake, all passed
RESULTC_RECV_32_FAILED = "HR2F" # Record version TLS 1.1 tested during handshake, failed
RESULTC_RECV_32_PASSED = "HR2P" # Record version TLS 1.1 tested during handshake, passed
RESULTC_RECV_33_FAILED = "HR3F" # Record version TLS 1.2 tested during handshake, failed
RESULTC_RECV_33_PASSED = "HR3P" # Record version TLS 1.2 tested during handshake, passed

TRESULTC_VALUES = (
	(RESULTC_CH_MINLEN_NOT_TESTED,	"Client Hello Minimum length not tested"),
	(RESULTC_CH_MINLEN_PASSED_256,	"Client Hello Minimum length 256 passed"),	
	(RESULTC_CH_MINLEN_FAILED_256,	"Client Hello Minimum length 256 failed"),
	(RESULTC_CH_MINLEN_FAILED_256_30,"Client Hello Minimum length 256 failed SSL v3"),
	(RESULTC_CH_MINLEN_FAILED_256_31,"Client Hello Minimum length 256 failed TLS 1.0"),
	(RESULTC_CH_MINLEN_FAILED_256_33,"Client Hello Minimum length 256 failed TLS 1.2"),
	(RESULTC_HIGHER_RECV_TEST, "Higher record versions than TLS 1.0 tested during handshake"),
	(RESULTC_HIGHER_RECV_NOTEST, "Higher record versions than TLS 1.0 not tested during handshake"),
	(RESULTC_RECV_ANY_FAILED, "Higher Record version tested during handshake, some failed"),
	(RESULTC_RECV_ANY_PASSED, "Higher Record version tested during handshake, all passed"),
	(RESULTC_RECV_32_FAILED, "Record version TLS 1.1 tested during handshake, failed"),
	(RESULTC_RECV_32_PASSED, "Record version TLS 1.1 tested during handshake, passed"),
	(RESULTC_RECV_33_FAILED, "Record version TLS 1.2 tested during handshake, failed"),
	(RESULTC_RECV_33_PASSED, "Record version TLS 1.2 tested during handshake, passed"),
				
				)

TRESULTC_VALUES_dict = dict(TRESULTC_VALUES)

# Check for duplicates and missing status codes

__values_set = {}
for __result_var in dir():
	if not __result_var.startswith("RESULTC_") or __result_var.startswith("RESULTC_VALUES"):
		continue
	if eval(__result_var) not in TRESULTC_VALUES_dict:
		raise Exception("Entry %s was not present in RESULTC_VALUES list" % (__result_var,))
	if eval(__result_var) in __values_set:
		print "Double entry in RESULTC_* enum values: ", __result_var, ". Matches ", __values_set[ eval(__result_var)]
		raise Exception("Double entry in RESULTC_* enum values: " + __result_var+ ". Matches "+ __values_set[ eval(__result_var)])
	__values_set[eval(__result_var)] = __result_var
		

if any([len([__y for __y in TRESULTC_VALUES if __x[0] == __y[0]])>1 for __x in TRESULTC_VALUES]):
	print "Double entry in RESULTC_* enum values"
	raise Exception("Double entry in RESULTC_* enum values")
if any([len([__y for __y in TRESULTC_VALUES if __x != __y and  __x[1] == __y[1]])>1 for __x in TRESULTC_VALUES]):
	print "Double explanation entry in RESULTC_* enum values", str([__z for __z in [[(__x,__y) for __y in TRESULTC_VALUES if __x != __y and __x[1] == __y[1]] for __x in TRESULTC_VALUES] if len(__z) > 1])
	raise Exception("Double explanation entry in RESULTC_* enum values" + str([__z for __z in [[(__x,__y) for __y in TRESULTC_VALUES if __x != __y and __x[1] == __y[1]] for __x in TRESULTC_VALUES] if len(__z) > 1]))

