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

def getInAcls(network):
	acls = {}
	for device in network["Devices"]:
		for acl in device["Acls"]:
			acls[(device["Name"], acl["Name"])] = acl

	acl_map = {}
	for device in network["Devices"]:
		for interface in device["Interfaces"]:
			acl = interface["InAcl"]
			if acl is None:
				acl_map[interface["Name"]] = None
			else:
				acl_map[interface["Name"]] = acls[(device["Name"], acl)]
			
	return acl_map
	
def getOutAcls(network):
	acls = {}
	for device in network["Devices"]:
		for acl in device["Acls"]:
			acls[(device["Name"], acl["Name"])] = acl

	acl_map = {}
	for device in network["Devices"]:
		for interface in device["Interfaces"]:
			acl = interface["OutAcl"]
			if acl is None:
				acl_map[interface["Name"]] = None
			else:
				acl_map[interface["Name"]] = acls[(device["Name"], acl)]
			
	return acl_map

def getStaticRoutes(network):
	static_routes = {}

	for device in network["Devices"]:
		for interface in device["Interfaces"]:
			static_routes[interface["Name"]] = device["StaticRoutes"]
	
	return static_routes

# def getTopologyDecl(neighbour):
# 	code = ""
# 	for i_src in neighbour.keys():
# 		for i_dst in neighbour.keys():
# 			if i_src != i_dst:
# 				code += "(declare-const datafwd_" + i_src + "_" + i_dst + " Bool)\n"
# 	code += "\n"
# 	for i_src in neighbour.keys():
# 		for i_dst in neighbour.keys():
# 			if i_src != i_dst:
# 				if neighbour[i_src] != i_dst:
# 					code += "(assert (= datafwd_" + i_src + "_" + i_dst + " False))\n"
# 	code += "\n"
# 	for i_src in neighbour.keys():
# 		for i_dst in neighbour.keys():
# 			if i_src != i_dst:
# 				if neighbour[i_src] == i_dst:
# 					code += "(assert (= datafwd_" + i_src + "_" + i_dst + " True))\n"
# 	return code

def getPacketConstraints(dstPrefixes, srcPrefixes, protocols, dstPorts, srcPorts):
	code = ""

	# DstIp Constraints
	code += printList(dstPrefixes, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_DstIp " + a[0] + ") (< Pkt_DstIp " + a[1] + "))")
	code += "\n"
	# SrcIp Constraints
	code += printList(srcPrefixes, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_SrcIp " + a[0] + ") (< Pkt_SrcIp " + a[1] + "))")
	code += "\n"
	# Protocol Constraints
	code += printList(protocols, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_Protocol " + a[0] + ") (< Pkt_Protocol " + a[1] + "))")
	code += "\n"	
	# DstPort Constraints
	code += printList(dstPorts, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_DstPort " + a[0] + ") (< Pkt_DstPort " + a[1] + "))")
	code += "\n"
	# DstPort Constraints
	code += printList(srcPorts, "(assert (or ", "))", " ", lambda a: "(and (>= Pkt_SrcPort " + a[0] + ") (< Pkt_SrcPort " + a[1] + "))")

	return code

def getReachabilityQuery(ingres, egress):
	code = ";; Reachability Queries\n"

	for i in ingres:
		for e in egress:
			code += "(assert (not canReach_" + i + "_" + e + "))\n"

	code += "\n(check-sat)\n(get-model)"

	return code

def getReachabilityConstraints(ingres, egress, devices, neighbours, fwd_edges):
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
				if interface != connected_interface and interface != dst:
					code += "(assert (= canReach_" + interface + "_" + dst + " datafwd_" + interface + "_" + connected_interface[(device, dst)] + "))\n"
					fwd_edges.append((interface, connected_interface[(device, dst)]))

	code += "\n"

	for dst in egress:
		for device in devices.keys():
			if not connected_interface[(device, dst)] is None:
				continue;
			for interface1 in devices[device]:
				code += "(assert (= canReach_" + interface1 + "_" + dst + " (or"
				for interface2 in devices[device]:
					if interface1 == interface2 or neighbours[interface2] is None:
						continue
					code += " (and datafwd_" + interface1 + "_" + interface2 + " canReach_" + neighbours[interface2] + "_" + dst + ")"
					fwd_edges.append((interface1, interface2))
				code += ")))\n"
		
	return code

def encodeRules(rules, default):
	if len(rules) == 0:
		if default == "Allow":
			return "true"
		else:
			return "false"

	rule = rules[0]

	code = "(ite (and "

	prefix = parsePrefix(rule["DstIp"])
	code += "(InRange Pkt_DstIp " + prefix[0] + " " + prefix[1] + ") "

	prefix = parsePrefix(rule["SrcIp"])
	code += "(InRange Pkt_SrcIp " + prefix[0] + " " + prefix[1] + ") "

	r = parseRange(rule["Protocol"])
	code += "(InRange Pkt_Protocol " + r[0] + " " + r[1] + ") "

	r = parseRange(rule["DstPort"])
	code += "(InRange Pkt_DstPort " + r[0] + " " + r[1] + ") "

	r = parseRange(rule["SrcPort"])
	code += "(InRange Pkt_SrcPort " + r[0] + " " + r[1] + ")) "

	code += "true " if rule["Action"] == "Allow" else "false "
	code += encodeRules(rules[1:], default) + ")"

	return code

def getDataplaneConstraints(fwd_edges, neighbours, in_acls, out_acls):
	code = "\n;; Encoding Dataplane Constraints\n";

	for edge in fwd_edges:
		code += "(declare-const datafwd_" + edge[0] + "_" + edge[1] + " Bool)\n"
	code += "\n"

	for edge in fwd_edges:
		in_acl = in_acls[edge[0]]
		out_acl = out_acls[edge[1]]
		postfix = "_" + edge[0] + "_" + edge[1]

		inAclEncoding = ""
		if in_acl is None:
			inAclEncoding = "true"
		else:
			inAclEncoding = encodeRules(in_acl["Rules"], in_acl["DefaultAction"])

		outAclEncoding = ""
		if out_acl is None:
			outAclEncoding = "true"
		else:
			outAclEncoding = encodeRules(out_acl["Rules"], out_acl["DefaultAction"])

		code += "(assert (= datafwd" + postfix + " (and ctrlfwd" + postfix + " " + inAclEncoding + " " + outAclEncoding + ")))\n"

	return code

def encodeRoutes(static_routes, edge):
	if len(static_routes) == 0:
		return "bestbgp_" + edge[0] + "_" + edge[1]

	route = static_routes[0]

	if route["Interface"] != edge[1]:
		return encodeRoutes(static_routes[1:], edge)
	
	prefix = parsePrefix(route["Prefix"])

	code = "(ite (InRange Pkt_DstIp " + prefix[0] + " " + prefix[1] + ") true " + encodeRoutes(static_routes[1:], edge) + ")"

	return code

def getRouteSelection(fwd_edges, devices, neighbours, static_routes, relevant_msgs):
	code = "\n;; Encoding Route Selection\n"

	for edge in fwd_edges:
		code += "(declare-const bestbgp_" + edge[0] + "_" + edge[1] + " Bool)\n"
	code += "\n"

	for edge in fwd_edges:
		for device in devices:
			if edge[0] in devices[device]:
				interfaces = devices[device]

		relevant_msgs.append(edge[1])
		condition = "(and msg_in_" + edge[1] + "_valid"
		for interface in interfaces:
			if interface == edge[0] or interface == edge[1]:
				continue
			relevant_msgs.append(interface)
			condition += " (InRange Pkt_DstIp msg_in_" + edge[1] + "_ip_min msg_in_" + edge[1] + "_ip_max)"
			condition += " (<= msg_in_" + edge[1] + "_length msg_in_" + interface + "_length)"
		condition += ")"
		
		code += "(assert (= bestbgp_" + edge[0] + "_" + edge[1] + " " + condition + "))\n"
	code += "\n"	

	# for edge in fwd_edges:
	# 	code += "(declare-const best_" + edge[0] + "_" + edge[1] + " Bool)\n"
	# code += "\n"

	# for edge in fwd_edges:
	# 	code += "(assert (= best_" + edge[0] + "_" + edge[1] + " " + encodeRoutes(static_routes[edge[0]], edge) + "))\n"
	# code += "\n"
	
	for edge in fwd_edges:
		code += "(declare-const ctrlfwd_" + edge[0] + "_" + edge[1] + " Bool)\n"
	code += "\n"

	for edge in fwd_edges:
		code += "(assert (= ctrlfwd_" + edge[0] + "_" + edge[1] + " " + encodeRoutes(static_routes[edge[0]], edge) + "))\n"

	return code

def getRouteAnnouncements(active_routing_edges, relevant_msgs):
	# TODO: Encode route announcements
	# TODO: Declare advertised routes
	# RUN!
	code = "\n;; Encoding Route Announcements\n"

	skip = []

	for src in relevant_msgs:
		if src in skip:
			continue
		else:
			skip.append(src)

		code += "(declare-const msg_in_" + src + "_valid Bool)\n"
		code += "(declare-const msg_in_" + src + "_length Int)\n"
		code += "(declare-const msg_in_" + src + "_ip_min Int)\n"
		code += "(declare-const msg_in_" + src + "_ip_max Int)\n"
		code += "(declare-const msg_in_" + src + "_ip_tag Int)\n"
	code += "\n"

	#exit()
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
	in_acls = getInAcls(network_config)
	out_acls = getOutAcls(network_config)
	static_routes = getStaticRoutes(network_config)

	# Generate z3 code
	packetDecl = getPacketDecl()

	for invariant in invariants['Reachability']:
		# Get packet constraints
		packetConstraints = getPacketConstraints(
			[parsePrefix(r) for r in invariant["DstIp"]],
			[parsePrefix(r) for r in invariant["SrcIp"]],
			[parseRange(r) for r in invariant["Protocol"]],
			[parseRange(r) for r in invariant["DstPort"]],
			[parseRange(r) for r in invariant["SrcPort"]]
		)

		active_routing_edges = []
		relevant_msgs = []

		# Encode reachability constraints and query
		reachability_constraints = getReachabilityConstraints(
			invariant["Ingress"], 
			invariant["Egress"],
			devices,
			neighbours,
			active_routing_edges
		)

		# Encode reachability query
		query = getReachabilityQuery(
			invariant["Ingress"], 
			invariant["Egress"]
		)

		# Encode data-plane constraints
		dataplane_constraints = getDataplaneConstraints(
			active_routing_edges,
			neighbours,
			in_acls,
			out_acls
		)

		# Encode route selection
		route_selection = getRouteSelection(
			active_routing_edges,
			devices,
			neighbours,
			static_routes,
			relevant_msgs
		)

		# Encode route announcements
		route_announcement = getRouteAnnouncements(
			active_routing_edges,
			relevant_msgs#,
			#devices,
			#neighbours,
			#static_routes
		)
		
		print "(define-fun InRange ((val Int) (ub Int) (lb Int)) Bool (and (>= val lb) (<= val ub)))\n\n" + \
		  packetDecl + "\n" + \
			packetConstraints + "\n" + \
			route_announcement + "\n" + \
			route_selection + "\n" + \
			dataplane_constraints + "\n" + \
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