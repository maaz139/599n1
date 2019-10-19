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
  def __call__(self, networkSpacePoints):
    res = []
    for networkSpacePoint in networkSpacePoints:
      header = networkSpacePoint[0]
      switch = networkSpacePoint[1]
      if self.topology.has_key(switch):
        for p in self.topology[switch]:
          res.append(tuple([header,p]))
    return res


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

  def sym_call(self, networkSpacePoint):
    header = networkSpacePoint[0]
    switch = networkSpacePoint[1]
    outgoing = set()
    if self.inBoundAcls.has_key(switch) and self.inBoundAcls[switch] is not None:
      inbound_acl_headers = self.inBoundAcls[switch].sym_check(header)
      if len(inbound_acl_headers) == 0:
        return set()
    else:
      inbound_acl_headers = [header]
    forwarding_points = []
    rt = self.routingTable[switch]
    for h in inbound_acl_headers:
      forwarding_points = forwarding_points + rt.sym_forward(h)
    outgoing = []
    for p in forwarding_points:
      if self.outBoundAcls.has_key(p[1]) and self.outBoundAcls[p[1]] is not None:
        outbound_acl_headers = self.outBoundAcls[p[1]].sym_check(p[0])
        for h in outbound_acl_headers:
          outgoing.append(tuple([h,p[1]]))
      else:
        outgoing.append(p)
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