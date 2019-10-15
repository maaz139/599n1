import sys
import yaml
from util import *

# Network transfer function is modelled as:
#   1. Apply InACL of the port at which packet arrives
#       - Apply rules in the order in which they are defined in config
#       - If no rule applies, use default action
#   2. Use forwarding table to send packet to output port on device 
#       - Apply longest matching prefix
#       - Drop packet if no rule matches
#   3. Apply OutAcl of the ports 

def main():
  network_fp = sys.argv[1]
  inv_fp = sys.argv[2]

  network_config = open(network_fp, "r").read();
  network_config = yaml.load(network_config, Loader=yaml.FullLoader)

  devices = []

  # Hash table that maps each port to a transfer function
  # that models an ACLs
  inBoundAcls = {}
  outBoundAcls = {}

  # Hash table that maps each port to a transfer function 
  # that models the forwarding table
  routingTable = {}

  for device in network_config["Devices"]:
    # Hash table that maps acl name to the tf object
    acls = {}
    
    for acl in device["Acls"]:
      acls[acl["Name"]] = Acl(acl)

    ft = ForwardingTable(device["ForwardingTable"])

    for interface in device["Interfaces"]:
      inBoundAcls[interface["Name"]] = acls[interface["InAcl"]] if interface["InAcl"] != None else None
      outBoundAcls[interface["Name"]] = acls[interface["OutAcl"]] if interface["OutAcl"] != None else None
      routingTable[interface["Name"]] = ft

if __name__== "__main__" :
  main()