import yaml
import sys
from pyDatalog import pyDatalog

###############################################################################
## Base Classes

class Fact:
	name = "undefined"
	args = []

	def __str__(self):
		return self.name + "(" + ", ".join([str(arg) for arg in self.args]) + ")"

	def __repr__(self):
		return str(self)

class Rule:
	premise =[]
	conclusion = Fact()

	def __str__(self):
		return self.name + "(" + ", ".join([str(arg) for arg in self.args]) + ")"

	def __repr__(self):
		return str(self)

class Route(pyDatalog.Mixin):
	def __init__(self, pre, pv, nh, t):
		super(Route, self).__init__()
		self.prefix = pre
		self.path_vec = pv
		self.next_hop = nh
		self.tags = t

	def __str__(self):
		return "(" + str(self.prefix) + ", " \
		           + str(self.path_vec) + ", " \
		           + str(self.next_hop) + ", " \
		           + str(self.tags) + ")"

	def __repr__(self):
		return str(self)

class Action:
	def __repr__(self):
		return str(self)

###############################################################################
## Derived Classes

class Neighbour(Fact):
	def __init__(self, src, dst):
		self.name = "neighbour"
		self.args = [src, dst]

class Announcement(Fact):
	def __init__(self, src, route):
		self.name = "advertisedRoute"
		self.args = [src, route]

class Interface(Fact):
	def __init__(self, device, interface):
		self.name = "deviceHasInterface"
		self.args = [device, interface]

###############################################################################
## Match expressions for policy clauses

class Matcher:
	def __repr__(self):
		return str(self)

class PrefixMatcher(Matcher):
	def __init__(self, prefix, mins, maxs):
		self.prefix_str = prefix
		self.min_size = int(mins)
		self.max_size = int(maxs)

	def matches(self, route):
		prefix = self.prefix.split("/")

		if not self.prefix_str == prefix[0]:
			psize = int(prefix[1])
			if psize >= self.min_size and psize <= self.max_size:
				return True

		return False

	def __str__(self):
		return self.prefix_str + "/[" + self.min_size + "-" + self.max_size + "]"

class TagMatcher(Matcher):
	def __init__(self, val):
		self.tag_value = val

	def matches(self, route):
		return route.tags.contains(self.tag_value)

	def __str__(self):
		return "tag: " + self.tag_value

###############################################################################
## Actions for policy clauses

class AddTag(Action):
	def __init__(self, t):
		self.tag = t

	def apply(route):
		route.tags.add(self.tag)
		return route

	def __str__(self):
		return "add tag " + str(self.tag)

class RemoveTag(Action):
	def __init__(self, t):
		self.tag = t

	def apply(route):
		route.tags.discard(self.tag)
		return route

	def __str__(self):
		return "remove tag " + str(self.tag)

class Allow(Action):
	def apply(route):
		return route

	def __str__(self):
		return "allow"

class Drop(Action):
	def apply(route):
		return None

	def __str__(self):
		return "drop"

###############################################################################

class Clause():
	def __init__(self, m, a):
		self.matchers = m
		self.actions = a

	def matches(self, route):
		for matcher in self.matcher:
			if not matcher.matches(route):
				return False # All must match
		return True

	def apply(self, route):
		r = route
		#print r
		for action in self.actions:
			r = action.apply(r)
			if r is None:
				return None
		#print r
		return r

class Policy():
 	def __init__(self, n, cls):
		self.name = n
		self.clauses = cls

###############################################################################

def getTerms(network_config):
	# Fact names
	static_terms = {"neighbour", "advertisedRoute", "deviceHasInterface"}

	devices = set([])
	interfaces = set([])

	# Devices & Intefaces
	for device in network_config["Devices"]:
		devices.add(device["Name"])
		for interface in device["Interfaces"]:
			interfaces.add(interface["Name"].replace('@',''))
	
	return {"facts": static_terms, "devices": devices, "interfaces": interfaces}

def getInterfaces(network_config):
	facts = []
	for device in network_config["Devices"]:
		for interface in device["Interfaces"]:
			facts.append(Interface(device["Name"], interface["Name"].replace('@','')))
	return facts

def getNeighbours(network_config):
	facts = []
	for device in network_config["Devices"]:
		for interface in device["Interfaces"]:
			if not interface["Neighbor"] is None:
				facts.append(Neighbour(interface["Name"].replace('@',''), interface["Neighbor"].replace('@','')))
	return facts

def getAnnouncements(network_config):
	facts = []
	for device in network_config["Devices"]:
		for interface in device["Interfaces"]:
			for prefix in device["BgpConfig"][0]["AdvertisedRoutes"]:
				facts.append(
					Announcement(
						device["Name"],											 	# Announcer
						Route(
							prefix, 														# Prefix announced
							[device["Name"]], 									# Path vector
							interface["Name"].replace('@',''),	# Next hop
							{}																	# Tags
						)
					)
				)
	return facts

# hears (interface2, route) <-
# (route, decision) = interface1_out_policy(oroute),
# decision == "allow",
#  announces(interface1, oroute),
#  neighbour(interface1, interface2)

def parseClauses(clauses_yaml):
	clauses = []
	for clause in clauses_yaml:
		matchers = []
		for expr in clause["Matches"]:
			pair = [e.strip() for e in expr.split(":")]
			if pair[0] == "prefix":
				expr = pair[1].split("/");
				srange = None
				if expr[1][0] == '[' and expr[1][-1] == ']':
					srange = [e.strip() for e in expr[1][1:-1].split("-")]	
				else:
					srange = [expr[1], expr[1]]
				matchers.append(PrefixMatcher(expr[0], srange[0], srange[1]))
			elif pair[0] == "tag":
				matchers.append(TagMatcher(pair[1]))
			else:
				print "NYI:", pair[0]
				exit()

		actions = []
		for action in clause["Actions"]:
			if action.startswith("add tag"):
				tag = action[7:].strip()
				actions.append(AddTag(tag))
			elif action.startswith("remove tag"):
				tag = action[7:].strip()
				actions.append(RemoveTag(tag))
			elif action == "allow":
				actions.append(Allow())
			elif action == "drop":
				actions.append(Drop())
			else:
				print "NYI:", action
				exit()
	
		clauses.append(Clause(matchers, actions))

	return clauses

def getInboundPolicies(network_config):
	policies = {}
	for device in network_config["Devices"]:
		for policy in device["BgpConfig"][1]["InboundPolicies"]:
			name = policy["Name"]
			clauses = parseClauses(policy["PolicyClauses"])
			policies[policy["Name"]] = Policy(name, clauses)

	policy_map = {}
	for device in network_config["Devices"]:
		for interface in device["Interfaces"]:
			if not interface["InBgpPolicy"] is None:
				policy_map[interface["Name"].replace('@','')] = policies[interface["InBgpPolicy"]]

	return policy_map

def getOutboundPolicies(network_config):
	policies = {}
	for device in network_config["Devices"]:
		for policy in device["BgpConfig"][2]["OutboundPolicies"]:
			name = policy["Name"]
			clauses = parseClauses(policy["PolicyClauses"])
			policies[policy["Name"]] = Policy(name, clauses)

	policy_map = {}
	for device in network_config["Devices"]:
		for interface in device["Interfaces"]:
			if not interface["OutBgpPolicy"] is None:
				policy_map[interface["Name"].replace('@','')] = policies[interface["OutBgpPolicy"]]

	return policy_map

###############################################################################

def batfish(terms, interfaces, neighbours, 
							announcements, inbound_policies,	outbound_policies):
	
	
	return 1
	#print(parent(bill,X)) # prints [('John Adams',)]


###############################################################################

def match(rr, case):
	return False

def foo(v):
	print v.v()
	return v

if __name__== "__main__" :
	###############################################################################
	## Parsing and initialization

	if len(sys.argv) != 3:
		print "Incorrect args: python batfish.py <network-file> <invariants-file>"
		exit()

	# Load network config fule
	network_fp = sys.argv[1]
	network_config = open(network_fp, "r").read()
	network_config = yaml.load(network_config, Loader=yaml.FullLoader)
	
	# Get routing rules from batfish
	terms = getTerms(network_config)
	interfaces = getInterfaces(network_config)
	neighbours = getNeighbours(network_config)
	announcements = getAnnouncements(network_config)
	inbound_policies = getInboundPolicies(network_config)
	outbound_policies = getOutboundPolicies(network_config)

	###############################################################################
	## For some reason pyDatalog doesn't work inside functions, hence inlined

	# Terms to represent facts, such as neighbours
	pyDatalog.create_terms("neighbour, advertisedRoute, deviceHasInterface, ribCandidate")

	# Neighbours relation between interfaces
	for n in neighbours:
		+(neighbour(n.args[0], n.args[1]))
	
	# Associate devices with their interfaces
	for i in interfaces:
		+(deviceHasInterface(i.args[0], i.args[1]))

	for a in announcements:
		# Reasoning about objects is for whatever reason
		# super slow, so I unroll the route class
		#+(advertisedRoute(a.args[0], a.args[1]))
		r = a.args[1]
		+(advertisedRoute(
			a.args[0], 
			r.prefix,
			r.path_vec,
			r.next_hop,
			list(r.tags)
		))
	
	# Rules to model route announcements
	pyDatalog.create_terms("Device1,Device2,Interface1,Interface2,Prefix,PathVector,NextHop,Tags")

	# This rule infers a candidate route 'R' available to
	# 'D1' for packets with ip prefix 'P'.
	#
	# Condition 1: Both devices must be connected
	# Condition 2: D2 advertises a route for prefix

	# Reasoning about objects is for whatever reason
	# super slow, so I unroll the route class
	#ribCandidate(Device1,Prefix,Route) <= deviceHasInterface(Device1,Interface1) & deviceHasInterface(Device2,Interface2) & neighbour(Interface1,Interface2) & advertisedRoute(Device2,Route) & Route.prefix[Route] == Prefix

	ribCandidate(Device1,Prefix,PathVector,NextHop,Tags) <= deviceHasInterface(Device1,Interface1) & deviceHasInterface(Device2,Interface2) & neighbour(Interface1,Interface2) & advertisedRoute(Device2,Prefix,PathVector,NextHop,Tags) #& 
		#allow_outbound_policy(Interface1,Route) & 
		#allow_inbound_policy(Interface1,Route)

	print ribCandidate(Device1,Prefix,PathVector,NextHop,Tags)
#	print ribCandidate('r1',Y)
	exit()

	rr = simulate_BGP()

	#print network_facts
	rr = None # TODO

	# Load invariants file
	inv_fp = sys.argv[2]
	invariants = open(inv_fp, "r").read()
	invariants = yaml.load(invariants, Loader=yaml.FullLoader)

	# Check invariant
	case_id = 0
	for case in invariants["RoutingRules"]:
		print "Checking case:", case_id

		if match(rr, case):
			print "Invariant correct: Routing rules match!"
			exit()
		
		case_id += 1

	print "Invariant incorrect: Routing rules don't match"