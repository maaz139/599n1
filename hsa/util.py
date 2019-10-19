
class Header:
  def __init__(self,srcIp,dstIp,srcPort,dstPort,prtcl):
    self.srcIp = srcIp
    self.dstIp = dstIp
    self.srcPort = srcPort
    self.dstPort = dstPort
    self.protocol = prtcl

  def __eq__(self, other):
    if isinstance(other, Header):
        return self.srcIp == other.srcIp and \
              self.dstIp == other.dstIp #and \
            #  self.srcPort == other.srcPort and \
            #  self.dstPort == other.dstPort and \
            #  self.protocol == other.protocol
    else:
      return False
  def __str__(self):
    return "(" + str(self.srcIp) + ", " \
               + str(self.dstIp) + ", " \
               + str(self.srcPort) + ", " \
               + str(self.dstPort) + ", " \
               + str(self.protocol) + ", "

  def __ne__(self,other):
    return not self.__eq__(other)

def make_new_sym_header():
  return Header(set(['x'*32]),set(['x'*32]),tuple([0,1000000]),tuple([0,1000000]),tuple([0,1000000]))

# if srcIp or dstIp is empty set, no packet can reach this state
def is_empty_sym_header(h):
  return len(h.srcIp) == 0 or len(h.dstIp) == 0

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
    return wce_match(header.dstIp, self.prefix)

  def sym_matches(self, h):
    matching_dstIp = wce_intersection(h.dstIp,set(["".join(self.prefix)]))
    return Header(h.srcIp, matching_dstIp, h.srcPort, h.dstPort, h.protocol)

  def compl_sym_matches(self, h):
    nonmatching_dstIp = wce_complement(wce_intersection(h.dstIp, set(["".join(self.prefix)])))
    return Header(h.srcIp, nonmatching_dstIp, h.srcPort, h.dstPort, h.protocol)

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
    sorted_rte = sorted(self.ft, key=get_prefix_size)
    sorted_rte.reverse()
    self.ft = sorted_rte

  def __call__(self, hs):
    for rte in self.ft:
      if rte.matches(hs):
        return set([rte.interface])
    return set()

  # input is header
  # output is list of header,switch pairs
  # output header now defines set of packets that can be sent to that switch
  def sym_forward(self,h):
    res = []
    # if we match a rule, it means we failed to match all previous rules
    # so maintain an expression that is intersection of complements of previous rules
    compls = h.dstIp
    # relies on RTEs being sorted by prefix
    for rte in self.ft:
      h.dstIp = compls
      hprime = rte.sym_matches(h)
      # if header can't reach this rule, we can ignore it
      if not is_empty_sym_header(hprime):
        hprime.dstIp = wce_intersection(hprime.dstIp,compls)
        res.append(tuple([hprime, rte.interface]))
        compls = wce_intersection(compls, wce_complement(set(["".join(rte.prefix)])))
    return res


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

def bit_intersect(b1, b2):
  if b1 == 'x':
    return b2
  elif b2 == 'x':
    return b1
  elif b1 == b2:
    return b1
  else:
    return 'z'

# Set operators for wildcard headers
def wce_intersection(wce1, wce2):
  # A intersect empty set = empty set
  if len(wce1) == 0 or len(wce2) == 0:
    return set()
  res = set()
  for e1 in wce1:
    for e2 in wce2:
      new_wce = "".join([bit_intersect(z[0],z[1]) for z in zip(e1, e2)])
      if 'z' not in new_wce:
        res.add(new_wce)
  return res

# some unions can be simplified, leave that for later
def wce_union(wce1, wce2):
  return wce1.union(wce2)

def wce_complement(wce):
  if len(wce) == 0:
    return set(['x'*32])
  if all([h == 'x'*32 for h in wce]):
    return set()
  res = set()
  for e in wce:
    for idx in range(len(e)):
      if e[idx] != 'x':
        comp = ['x'] * len(e)
        if e[idx] == '1':
          comp[idx] = '0'
        else:
          comp[idx] = '1'
        res.add("".join(comp))
  return res

def wce_difference(wce1, wce2):
  return wce_intersection(wce1,wce_complement(wce2))

def e_in_wce(e, wce):
  return len(wce_intersection(set([e]), wce)) != 0
