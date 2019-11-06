import sys
import yaml
from util import *

DEBUG = False

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
          if i['Name'] in self.topology:
            self.topology[i['Name']].add(i['Neighbor'])
          else:
            self.topology[i['Name']] = set([i['Neighbor']])

  # take one header/switch tuple, return set of header/switch tuples
  def __call__(self, networkSpacePoints):
    res = []
    packets_dropped = []
    for networkSpacePoint in networkSpacePoints:
      header = networkSpacePoint[0]
      switch = networkSpacePoint[1]
      if switch in self.topology:
        if len(self.topology[switch]) == 0:
          packets_dropped.append(switch)
        for p in self.topology[switch]:
          res.append(tuple([header,p]))
      else:
        packets_dropped.append(switch)
    return (packets_dropped, res)


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
    packets_dropped = False

    if DEBUG:
      print("=======================================================================================\n")
      print ("#### APPLYING INGRESS ACLS ####\n")
    header = networkSpacePoint[0]
    switch = networkSpacePoint[1]
    if switch in self.inBoundAcls and self.inBoundAcls[switch] is not None:
      acl_output = self.inBoundAcls[switch].sym_check(header)
      packets_dropped = packets_dropped or acl_output[0]
      inbound_acl_headers = acl_output[1]
      if len(inbound_acl_headers) == 0:
        return (packets_dropped, set())
    else:
      inbound_acl_headers = [header]

    if DEBUG:
      print("HEADER SPACE AFTER IN ACLS:\n" + str(inbound_acl_headers) + "\n")
      print("=======================================================================================\n")

    if DEBUG:
      print ("#### FORWARDING PACKETS ####\n")
    forwarding_points = []
    rt = self.routingTable[switch]
    for h in inbound_acl_headers:
      res = rt.sym_forward(h)
      packets_dropped = packets_dropped or res[0]
      forwarding_points = forwarding_points + res[1]
    
    if DEBUG:
      print ("HEADER SPACE AFTER FORWARDING:\n" + str(forwarding_points) + "\n")
    
      print("=======================================================================================\n")
      print ("#### APPLYING OUTGRESS ACLS ####\n")

    outgoing = []
    for p in forwarding_points:
      if DEBUG:
        print ("HEADER: " + str(p) + "\n")
      if p[1] in self.outBoundAcls and self.outBoundAcls[p[1]] is not None:
        acl_output = self.outBoundAcls[p[1]].sym_check(p[0])
        packets_dropped = packets_dropped or acl_output[0]
        outbound_acl_headers = acl_output[1]
        for h in outbound_acl_headers:
          outgoing.append(tuple([h,p[1]]))
      else:
        outgoing.append(p)
      if DEBUG:
        print ("HEADER AFER ACL: " + str(outgoing) + "\n")

    if DEBUG:
      print ("HEADER SPACE AFTER OUT ACLS:\n" + str(outgoing) + "\n")
      print("=======================================================================================\n")

    return (packets_dropped, outgoing)

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