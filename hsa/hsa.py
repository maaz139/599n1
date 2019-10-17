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

class TopologyFunction:
  def __init__(self,network):
    self.topology = {}
    for d in network['Devices']:
      for i in d['Interfaces']:
        if i['Neighbor'] is not None:
          if self.topology.has_key(i['Name']):
            self.topology[i['Name']].add(i['Neighbor'])
          else:
            self.topology[i['Name']] = set([i['Neighbor']])

  # take one header/switch tuple, return set of header/switch tuples
  def __call__(self, networkSpacePoint):
    header = networkSpacePoint[0]
    switch = networkSpacePoint[1]
    if self.topology.has_key(switch):
      return set([tuple([header, p]) for p in self.topology[switch]])
    else:
      return set()


class TransferFunctions:
  def __init__(self, network):
    self.inBoundAcls = {}
    self.outBoundAcls = {}
    self.routingTable = {}
    for device in network["Devices"]:
      # Hash table that maps acl name to the tf object
      acls = {}

      for acl in device["Acls"]:
        acls[acl["Name"]] = Acl(acl)

      ft = ForwardingTable(device["ForwardingTable"])

      for interface in device["Interfaces"]:
        self.inBoundAcls[interface["Name"]] = acls[interface["InAcl"]] if interface["InAcl"] != None else None
        self.outBoundAcls[interface["Name"]] = acls[interface["OutAcl"]] if interface["OutAcl"] != None else None
        self.routingTable[interface["Name"]] = ft

  # take one header/switch tuple, return set of header/switch tuples
  def __call__(self, networkSpacePoint):
    header = networkSpacePoint[0]
    switch = networkSpacePoint[1]
    outgoing = set()
    if self.check_inbound_acl(header, switch) == "Deny":
      return outgoing
    local_interface_set = self.routingTable[switch](header)
    if len(local_interface_set) == 0:
      return outgoing
    else:
      for interface in local_interface_set:
        if self.check_outbound_acl(header, interface) == "Allow":
          outgoing.add(tuple([header, interface]))
    return outgoing

  def check_inbound_acl(self, header, switch):
    acl = self.inBoundAcls[switch]
    if acl is not None:
      return acl(header)
    else:
      return "Allow"

  def check_outbound_acl(self, header, switch):
    acl = self.outBoundAcls[switch]
    if acl is not None:
      return acl(header)
    else:
      return "Allow"




def main():
  network_fp = sys.argv[1]
  inv_fp = sys.argv[2]

  network_config = open(network_fp, "r").read();
  network_config = yaml.load(network_config, Loader=yaml.FullLoader)

  topology = TopologyFunction(network_config)
  transfer = TransferFunctions(network_config)

if __name__== "__main__" :
  main()