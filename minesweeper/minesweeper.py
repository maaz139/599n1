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

	code = ";; Encoding Packet Constraints\n"
	for field in fields:
		code += "(declare-const " + prefix + field + " Int)\n"
	return code

def getNeighbours(network):
	neighbour = {}
	for device in network["Devices"]:
		for interface in device["Interfaces"]:
			neighbour[interface["Name"]] = interface["Neighbor"]
	return neighbour

def getDevices(network):
	devices = {}
	for device in network["Devices"]:
		devices[device["Name"]] = []
		for interface in device["Interfaces"]:
			devices[device["Name"]].append(interface["Name"])
	return devices

def getTopologyDecl(neighbour):
	code = ""
	for i_src in neighbour.keys():
		for i_dst in neighbour.keys():
			if i_src != i_dst:
				code += "(declare-const datafwd_" + i_src + "_" + i_dst + " Bool)\n"
	code += "\n"
	for i_src in neighbour.keys():
		for i_dst in neighbour.keys():
			if i_src != i_dst:
				if neighbour[i_src] != i_dst:
					code += "(assert (= datafwd_" + i_src + "_" + i_dst + " False))\n"
	code += "\n"
	for i_src in neighbour.keys():
		for i_dst in neighbour.keys():
			if i_src != i_dst:
				if neighbour[i_src] == i_dst:
					code += "(assert (= datafwd_" + i_src + "_" + i_dst + " True))\n"
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

def getReachabilityQuery(ingres, egress):
	code = ";; Reachability Queries\n"

	for i in ingres:
		for e in egress:
			code += "(assert (not canReach_" + i + "_" + e + "))\n"

	return code

def getReachabilityConstraints(ingres, egress, devices, neighbours):
	code = "\n;; Encoding Reachability Constraints\n";

	# Declare reachability variable for each interface that is not dst
	for dst in egress:
		for device in devices.keys():
			for interface in devices[device]:
				if interface != dst:
					code += "(declare-const canReach_" + interface + "_" + dst + " Bool)\n"
	code += "\n"
	
	# Find connected interfaces
	connected_interface = {}
	for dst in egress:
		for device in devices.keys():
			# Is device connected to dst?
			connected = None
			for interface in devices[device]:
				if interface == dst or neighbours[interface] == dst:
					connected = interface

			connected_interface[(device, dst)] = connected

	# Interfaces can reach dst if they route to an interface that can reach dst			
	for dst in egress:
		for device in devices.keys():
			if connected_interface[(device, dst)] is None:
				continue
			for interface in devices[device]:
				if interface != connected_interface:
					code += "(assert (= canReach_" + interface + "_" + dst + " datafwd_" + interface + "_" + connected_interface[(device, dst)] + "))\n"

	code += "\n"

	for dst in egress:
		for device in devices.keys():
			if not connected_interface[(device, dst)] is None:
				continue;
			for interface1 in devices[device]:
				code += "(= canReach_" + interface1 + "_" + dst + " (or"
				for interface2 in devices[device]:
					if neighbours[interface2] is None:
						continue
					code += " (and datafwd_" + interface1 + "_" + interface2 + " canReach_" + neighbours[interface2] + "_" + dst + ")"
				code += "))\n"
		
	return code

###############################################################################
## Parsing and initialization

def main():
	if len(sys.argv) != 3:
		raise Exception("Incorrect args: python batfish.py <network-file> <invariants-file>")

	# Load network config fule
	network_fp = sys.argv[1]
	network_config = open(network_fp, "r").read()
	network_config = yaml.load(network_config, Loader=yaml.FullLoader)

	# Load invariants file
	inv_fp = sys.argv[2]
	invariants = open(inv_fp, "r").read()
	invariants = yaml.load(invariants, Loader=yaml.FullLoader)

	# Parse network
	devices = getDevices(network_config)
	neighbours = getNeighbours(network_config)

	packetDecl = getPacketDecl()
	topologyDecl = getTopologyDecl(neighbours)

	for invariant in invariants['Reachability']:
		# Get packet constraints
		packetConstraints = getPacketConstraints(
			[parsePrefix(r) for r in invariant["DstIp"]],
			[parsePrefix(r) for r in invariant["SrcIp"]],
			[parseRange(r) for r in invariant["Protocol"]],
			[parseRange(r) for r in invariant["DstPort"]],
			[parseRange(r) for r in invariant["SrcPort"]]
		)

		# Encode reachability constraints and query
		reachability_constraints = getReachabilityConstraints(
			invariant["Ingress"], 
			invariant["Egress"],
			devices,
			neighbours
		)

		# Encode reachability query
		query = getReachabilityQuery(
			invariant["Ingress"], 
			invariant["Egress"]
		)

		# Encode data-plane constraints
		dataplane_constraints = getDataplaneConstraints
		
		print packetDecl + "\n" + \
			packetConstraints + "\n" + \
			reachability_constraints + "\n" + \
			query
		
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