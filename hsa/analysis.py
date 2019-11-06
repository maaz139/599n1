import yaml
import sys
from hsa import TopologyFunction, TransferFunctions
from util import make_new_sym_header, ip_to_wce_set

def reachability(network, invariant, d):
  gamma = TopologyFunction(network)
  psi = TransferFunctions(network)
  ingress = invariant['Ingress']
  egress = invariant['Egress']
  init_header = make_new_sym_header()
  init_header.srcIp = ip_to_wce_set(invariant['SrcIp'][0])
  init_header.dstIp = ip_to_wce_set(invariant['DstIp'][0])
  current_round = [tuple([init_header, loc]) for loc in ingress]

  # Edge case: ingress == outgress
  current_round = list(filter(lambda p: p[1] not in egress, current_round))

  i = 0
  next_round = []
  while len(current_round) > 0:
    print ("############# REACHABILITY ROUND " + str(i) + " #############\n")
    print ("Starting Packet Set:\n" + str(current_round) + "\n")#, "\n"

    for p in current_round:
      res = psi.sym_call(p)
      pkts_dropped = res[0]
      forwarded = res[1]
      if pkts_dropped: 
        return False
      res = gamma(forwarded)
      pkts_dropped = res[0]
      forwarded = res[1]
      next_round = next_round + forwarded

    current_round = next_round
    next_round = []
    
    i = i + 1

    input("Press Enter to continue...")
  return False

def main():
  network_fp = sys.argv[1]
  inv_fp = sys.argv[2]

  network_config = open(network_fp, "r").read();
  network_config = yaml.load(network_config, Loader=yaml.FullLoader)

  invariants = open(inv_fp, "r").read()
  invariants = yaml.load(invariants, Loader=yaml.FullLoader)

  solutions = [False, True, False, False, True, True, True, False, True, False, False, False]

  # traffic to loopback should not be reachable in general
  c = 0
  for invariant in invariants:
    if not c == 1: c = c + 1; continue
    #print invariant
    if reachability(network_config,invariant,5) == solutions[c]:
      print ("Success: Invariant " + str(c) + "\n")
    else:
      print ("Failure: Invariant " + str(c) + "\n")
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