
class Header:
  def __init__(self,srcIp,dstIp,srcPort,dstPort,prtcl):
    self.srcIp = srcIp
    self.dstIp = dstIp
    self.srcPort = srcPort
    self.dstPort = dstPort
    self.protocol = prtcl
  def __key(self):
    return (self.srcIp,self.dstIp,self.srcPort,self.dstPort,self.protocol)
  def __hash__(self):
    return hash(self.__key())
  def __eq__(self, other):
    if isinstance(other, Header):
        return self.__key() == other.__key()
    return NotImplemented

class Rule:
  '''
  A class implementing a rule in the acl.
  '''

  def __init__(self, rdict):
    self.srcIp = ip_to_wce(rdict["SrcIp"])
    self.dstIp = ip_to_wce(rdict["DstIp"])
    self.srcPort = port_to_tuple(rdict["SrcPort"])
    self.dstPort = port_to_tuple(rdict["DstPort"])
    self.protocol = protocol_to_tuple(rdict["Protocol"])
    self.action = rdict["Action"]

  def matches(self, h):
    return wce_match_against_decimal_ip(self.srcIp, h.srcIp) and \
           wce_match_against_decimal_ip(self.dstIp, h.dstIp) and \
           match_range(self.srcPort, h.srcPort) and \
           match_range(self.dstPort, h.dstPort) and \
           match_range(self.protocol, h.protocol)

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
      self.rules.append(Rule(rule))

  def __call__(self, hs):
    for r in self.rules:
      if r.matches(hs):
        return r.action
    return self.default

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

  def matches(self, header):
    wce_dst = ip_to_wce(header.dstIp + "/32")
    return wce_match(wce_dst, self.prefix)

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
    self.ft = []
    for entry in table:
      prefix = ip_to_wce(entry["Prefix"])
      prefix_size = int(entry["Prefix"].split("/")[1])
      interface = entry["Interface"]
      self.ft.append(RTEntry(prefix, prefix_size, interface))
    # store routing rules by prefix length so we can easily do longest prefix matching
    self.ft = sorted(self.ft, key=get_prefix_size)

  def __call__(self, hs):
    for rte in self.ft:
      if rte.matches(hs):
        return set([rte.interface])
    return set()

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
  return tuple([int(p) for p in protocol_str.split("-")])

def port_to_tuple(port_str):
  return tuple([int(p) for p in port_str.split("-")])

def match_range(range,val):
  return range[0] <= val and range[1] >= val

def get_prefix_size(rte):
  return rte.prefix_size

def bit_match(b1,b2):
  return b1 == b2 or b1 == 'x' or b2 == 'x'

def wce_match(wce1, wce2):
  return all([bit_match(z[0],z[1]) for z in zip(wce1,wce2)])

def wce_match_against_decimal_ip(wce1, ip):
    wce_ip = ip_to_wce(ip + "/32")
    return wce_match(wce_ip, wce1)
