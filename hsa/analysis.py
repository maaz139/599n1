import yaml
import sys
from hsa import TopologyFunction, TransferFunctions
from util import make_new_sym_header, ip_to_wce_set, port_to_tuple

DEBUG = False

def reachability(network, invariant):
  gamma = TopologyFunction(network)
  psi = TransferFunctions(network)
  ingress = invariant['Ingress']
  egress = invariant['Egress']
  init_headers = []
  for sip in invariant['SrcIp']:
    for dip in invariant['DstIp']:
        init_header = make_new_sym_header()
        init_header.srcIp = ip_to_wce_set(sip)
        init_header.dstIp = ip_to_wce_set(dip)
        init_header.protocol = port_to_tuple(invariant["Protocol"][0]) # More head in sand situation, only one port range :D
        init_header.srcPort = port_to_tuple(invariant["SrcPort"][0]) # More head in sand situation, only one port range :D
        init_header.dstPort = port_to_tuple(invariant["DstPort"][0]) # More head in sand situation, only one port range :D
        init_headers.append(init_header)
  current_round = []
  for init_header in init_headers:
    current_round += [tuple([init_header, loc]) for loc in ingress]

  # Edge case: ingress == outgress
  current_round = list(filter(lambda p: p[1] not in egress, current_round))

  i = 0
  next_round = []
  while len(current_round) > 0:
    if DEBUG:
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
      
      if any([switch not in egress for switch in pkts_dropped]):
        return False

      next_round = next_round + forwarded

    current_round = next_round
    next_round = []
    
    i = i + 1

    if DEBUG:
      input("Press Enter to continue...")
  return True

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
    #if not c == 9: c = c + 1; continue
    t = reachability(network_config,invariant)
    #if DEBUG:
    print(t)
    if t == solutions[c]:
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