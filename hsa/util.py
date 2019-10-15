class Rule:
  '''
  A class implementing a rule in the acl.
  '''

  def __init__(self, srcip, dstip, srcport, dstport, prtcl, action):
    self.srcIp = srcip
    self.dstIp = dstip
    self.srcPort = srcport
    self.dstPort = dstport
    self.protocol = prtcl
    self.action = action

  def matches(self, srcip, dstip, srcport, dstport, prtcl):
    return False

  def __str__(self):
    return "(" + str(self.srcIp) + ", " \
               + str(self.dstIp) + ", " \
               + str(self.srcPort) + ", " \
               + str(self.dstPort) + ", " \
               + str(self.protocol) + ", " \
               + str(self.action) + ")"

  def __repr__(self):
    return str(self)

class Acl:
  '''
  A class implementing an access control list.
  '''

  def __init__(self, acl):
    self.name = acl["Name"]

    # Default action
    self.default = acl["DefaultAction"]

    # Ordered list of rules
    self.rules = []

    for rule in acl["Rules"]:
      srcIp = ip_to_wce(rule["SrcIp"])
      dstIp = ip_to_wce(rule["DstIp"])
      srcPort = port_to_tuple(rule["SrcPort"])
      dstPort = port_to_tuple(rule["DstPort"])
      protocol = protocol_to_tuple(rule["Protocol"])
      action = rule["Action"]
      self.rules.append(Rule(srcIp, dstIp, srcPort, dstPort, protocol, action))

  def __call__(self, hs):
    pass# TODO

  def __str__(self):
    return self.name

  def __repr__(self):
    return str(self)

class RTEntry:
  '''
  A class implementing an entry in the routing table.
  '''

  def __init__(self, prefix, size, interface):
    self.prefix = prefix
    self.prefix_size = size
    self.interface = interface

  def matches(self, dst):
    return False

  def __str__(self):
    return "(" + str(self.prefix) + ", " \
               + str(self.prefix_size) + ", " \
               + str(self.interface) + ")"

  def __repr__(self):
    return str(self)


class ForwardingTable:
  '''
  A class implementing a forwarding table.
  '''

  def __init__(self, table):
    for entry in table:
      prefix = ip_to_wce(entry["Prefix"])
      prefix_size = int(entry["Prefix"].split("/")[1])
      interface = entry["Interface"]
      ft.append(RTEntry(prefix, prefix_size, interface))

  def __call__(self, hs):
    pass# TODO

  def __str__(self):
    return self.name

  def __repr__(self):
    return str(self)

## Util methods ##
def ip_to_wce(ip_str):
  prefix_length = int(ip_str.split("/")[1])
  prefix = ip_str.split("/")[0]

  wce = ''.join([bin(int(x)+256)[3:] for x in prefix.split('.')])
  wce = [l for l in wce]

  for idx in range(int(prefix_length), 32):
    wce[idx] = 'x'
  
  return wce

def protocol_to_tuple(protocol_str):
  return tuple(protocol_str.split("-"))

def port_to_tuple(port_str):
  return tuple(port_str.split("-"))