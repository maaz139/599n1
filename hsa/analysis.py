import yaml
import sys
from hsa import TopologyFunction, TransferFunctions
from util import make_new_sym_header, ip_to_wce_set

def reachability(network, invariant, d):
  gamma = TopologyFunction(network)
  psi = TransferFunctions(network)
  ingress = invariant['Ingress'][0]
  egress = invariant['Egress'][0]
  init_header = make_new_sym_header()
  init_header.srcIp = ip_to_wce_set(invariant['SrcIp'][0])
  init_header.dstIp = ip_to_wce_set(invariant['DstIp'][0])
  init_point = tuple([init_header, ingress])
  current_round = [init_point]
  next_round = []
  for i in range(d):
    #print "Reachability round " + str(i) 
    #print current_round#, "\n"
    
    for p in current_round:
      next_round = next_round + gamma(psi.sym_call(p))

    if any([p[1] == egress for p in next_round]):
      return True
    current_round = next_round
    next_round = []
  return False

def main():
  network_fp = sys.argv[1]
  inv_fp = sys.argv[2]

  network_config = open(network_fp, "r").read();
  network_config = yaml.load(network_config, Loader=yaml.FullLoader)

  invariants = open(inv_fp, "r").read()
  invariants = yaml.load(invariants, Loader=yaml.FullLoader)

  # traffic to loopback should not be reachable in general
  c = 0
  for invariant in invariants:
    #print invariant
    if not reachability(network_config,invariant,5):
      print "Success: Invariant " + str(c) + "\n"
    else:
      print "Failure: Invariant " + str(c) + "\n"
    c = c + 1
        
  #invariant0 = invariants[0]
  #if not reachability(network_config,invariant0,5):
  #  print "Success: traffic to loopback should not be reachable in general\n"
  #else:
  #  print "Invariant 0 failed\n"

  # traffic to loopback should be reachable in from the right source
  #invariant1 = invariants[1]
  #if not reachability(network_config,invariant1,5):
  #  print "Success: traffic to loopback should be reachable in from the right source\n"
  #else:
  #  print "Invariant 1 failed\n"

  # traffic between hosts should be reachable for UDP
  #invariant6 = invariants[6]
  #if reachability(network_config,invariant6,5):
   # print "Traffic between hosts should be reachable for UDP\n"
  #else:
   # print "Invariant6 failed\n"

if __name__== "__main__" :
  main()