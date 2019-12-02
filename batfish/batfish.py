import yaml
import sys

###############################################################################
## Base Classes

class Fact:
	name = "Undefined"
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

class Route:
	def __init__(self, pre, pv, nh, t):
		self.prefix = pre
		self.path_vec = pv
		self.next_hop = nh
		self.tags = t

	def __str__(self):
		return "(" + str(self.prefix) + ", " \
		           + str(self.path_vec) + "," \
		           + str(self.next_hop) + "," \
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
		self.name = "Neighbour"
		self.args = [src, dst]

class Announcement(Fact):
	def __init__(self, src, route):
		self.name = "AdvertisedRoute"
		self.args = [src, route]

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
		return self.tags.contains(self.tag_value)

	def __str__(self):
		return "tag: " + self.tag_value

###############################################################################
## Actions for policy clauses

class AddTag(Action):
	def __init__(self, t):
		self.tag = t

	def apply(route):
		route.tags.append(self.tag)
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

def getNeighbours(network_config):
	facts = []
	for device in network_config["Devices"]:
		for interface in device["Interfaces"]:
			if not interface["Neighbor"] is None:
				facts.append(Neighbour(interface["Name"], interface["Neighbor"]))
	return facts

def getAnnouncements(network_config):
	facts = []
	for device in network_config["Devices"]:
		for interface in device["Interfaces"]:
			for prefix in device["BgpConfig"][0]["AdvertisedRoutes"]:
				facts.append(
					Announcement(
						interface["Name"], 	# Announcer
						Route(
							prefix, 						# Prefix announced
							[device["Name"]], 	# Path vector
							interface["Name"],	# Next hop
							{}									# Tags
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
				policy_map[interface["Name"]] = policies[interface["InBgpPolicy"]]

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
				policy_map[interface["Name"]] = policies[interface["OutBgpPolicy"]]

	return policy_map

###############################################################################

def match(rr, case):
	return False

def main():
	if len(sys.argv) != 3:
		print "Incorrect args: python batfish.py <network-file> <invariants-file>"
		exit()

	# Load network config fule
	network_fp = sys.argv[1]
	network_config = open(network_fp, "r").read()
	network_config = yaml.load(network_config, Loader=yaml.FullLoader)
	
	# Get routing rules from batfish
	neighbours = getNeighbours(network_config)
	announcements = getAnnouncements(network_config)
	inbound_policies = getInboundPolicies(network_config)
	outbound_policies = getOutboundPolicies(network_config)
	
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

if __name__== "__main__" :
	main()