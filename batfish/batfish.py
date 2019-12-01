import yaml
import sys
#from hsa import TopologyFunction, TransferFunctions
#from util import make_new_sym_header, ip_to_wce_set, port_to_tuple

def match(rr, case):
	return False

def main():
	if len(sys.argv) != 3:
		print "Incorrect args: python batfish.py <network-file> <invariants-file>"
		exit()

	# Load network config fule
	network_fp = sys.argv[1]
	network_config = open(network_fp, "r").read();
	network_config = yaml.load(network_config, Loader=yaml.FullLoader)
	
	# Get routing rules from batfish
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