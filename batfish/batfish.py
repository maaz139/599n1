import yaml
import sys
#from hsa import TopologyFunction, TransferFunctions
#from util import make_new_sym_header, ip_to_wce_set, port_to_tuple

###############################################################################

class Fact:
	name = "Undefined"
	args = []

	def __str__(self):
		return self.name + "(" + ", ".join(self.args) + ")"

	def __repr__(self):
		return str(self)

class Neighbour(Fact):
	def __init__(self, src, dst):
		self.name = "Neighbour"
		self.args = [src, dst]

class Announcement(Fact):
	def __init__(self, src, route):
		self.name = "AdvertisedRoute"
		self.args = [src, route]

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
			for route in device["BgpConfig"][0]["AdvertisedRoutes"]:
				facts.append(Announcement(interface["Name"], route))
		print facts
	return facts

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
	network_facts = getNeighbours(network_config)
	network_facts += getAnnouncements(network_config)
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