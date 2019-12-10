import yaml
import sys
import socket
import struct

###############################################################################
## Util funcs

def NYI():
	raise Exception("Not yet implemented.")

def ip(ones, reverse=False):
	ip = ''
	if not reverse:
		for one in range(0, ones):
			ip += '1'
		for zero in range(0, 32-ones):
			ip += '0'
	else:
		for one in range(0, 32-ones):
			ip += '0'
		for zero in range(0, ones):
			ip += '1'
	return int(ip, 2)

def parsePrefix(raw_str):
	r = raw_str.split("/")
	addr = r[0]
	size = int(r[1])
	minv = ip2int(addr) & ip(size)
	maxv = ip2int(addr) | ip(32-size, True)
	return (str(minv), str(maxv))

def parseRange(raw_str):
	r = raw_str.split("-")
	return (r[0], r[1])

def printList(l, pre, post, delim, foo):
	return pre + delim.join([foo(v) for v in l]) + post

def ip2int(addr):
  return struct.unpack("!I", socket.inet_aton(addr))[0]

###############################################################################

def getPacketDecl():
	# One global packet defination (SMT-Lib2 syntax)
	prefix = "Pkt_"
	fields = ["DstIp", "SrcIp", "DstPort", "SrcPort", "Protocol"]

	code = ""
	for field in fields:
		code += "(declare-const " + prefix + field + " Int)\n"

	#print code
	return code

def getPacketConstraints(dstPrefixes, srcPrefixes, protocols, dstPorts, srcPorts):
	code = ""
	
	# DstIp Constraints
	code += printList(dstPrefixes, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_DstIp " + a[0] + ") (< Pkt_DstIp " + a[1] + ")")

	code += "\n"

	# SrcIp Constraints
	code += printList(srcPrefixes, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_SrcIp " + a[0] + ") (< Pkt_SrcIp " + a[1] + ")")

	code += "\n"
	
	# Protocol Constraints
	code += printList(protocols, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_Protocol " + a[0] + ") (< Pkt_Protocol " + a[1] + ")")

	code += "\n"
	
	# DstPort Constraints
	code += printList(dstPorts, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_DstPort " + a[0] + ") (< Pkt_DstPort " + a[1] + ")")

	code += "\n"
	
	# DstPort Constraints
	code += printList(srcPorts, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_SrcPort " + a[0] + ") (< Pkt_SrcPort " + a[1] + ")")

	return code

###############################################################################
## Parsing and initialization

def main():
	if len(sys.argv) != 3:
		print "Incorrect args: python batfish.py <network-file> <invariants-file>"
		exit()

	# Load network config fule
	network_fp = sys.argv[1]
	network_config = open(network_fp, "r").read()
	network_config = yaml.load(network_config, Loader=yaml.FullLoader)

	# Load invariants file
	inv_fp = sys.argv[2]
	invariants = open(inv_fp, "r").read()
	invariants = yaml.load(invariants, Loader=yaml.FullLoader)

	packetDecl = getPacketDecl()

	for invariant in invariants['Reachability']:
		packetConstraints = getPacketConstraints(
			[parsePrefix(r) for r in invariant["DstIp"]],
			[parsePrefix(r) for r in invariant["SrcIp"]],
			[parseRange(r) for r in invariant["Protocol"]],
			[parseRange(r) for r in invariant["DstPort"]],
			[parseRange(r) for r in invariant["SrcPort"]]
		)

		print packetDecl + "\n" + packetConstraints
		
		exit()

	#exit()

	# Check invariant
	# case_id = 0
	# for case in invariants["RoutingRules"]:
	# 	print "Checking case:", case_id

	# 	if match(rr, case):
	# 		print "Invariant correct: Routing rules match!"
	# 		exit()
		
	# 	case_id += 1

	# print "Invariant incorrect: Routing rules don't match"

if __name__== "__main__" :
	main()