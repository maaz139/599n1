import yaml
import sys
from pyDatalog import pyDatalog

###############################################################################
## Base Classes

class Fact:
  name = "undefined"
  args = []

  def __str__(self):
    return self.name + "(" + ", ".join([str(arg) for arg in self.args]) + ")"

  def __repr__(self):
    return str(self)

  def assertFact(self):
    pyDatalog.load("+(" + self.__str__() + ")")

  def retractFact(self):
    pyDatalog.load("-(" + self.__str__() + ")")

class Rule:
  premise =[]
  conclusion = Fact()

  def __str__(self):
    return self.name + "(" + ", ".join([str(arg) for arg in self.args]) + ")"

  def __repr__(self):
    return str(self)

class Route:
  def __init__(self, pre, pv, nh, t):
    self.prefix = pre
    self.path_vec = pv
    self.next_hop = nh
    self.tags = t

  def __str__(self):
    return "(" + str(self.prefix) + ", " \
               + str(self.path_vec) + "," \
               + str(self.next_hop) + "," \
               + str(self.tags) + ")"

  def __repr__(self):
    return str(self)

class Action:
  def __repr__(self):
    return str(self)
  def getActionTuple(self):
    return ("null","null")

###############################################################################
## Derived Classes

class Neighbour(Fact):
  def __init__(self, src, dst):
    self.name = "neighbour"
    self.args = [src, dst]

class Announcement(Fact):
  def __init__(self, src, route):
    self.name = "advertisedRoute"
    self.args = [src, route]

class Interface(Fact):
  def __init__(self, device, interface):
    self.name = "deviceHasInterface"
    self.args = [device, interface]

###############################################################################

class AnnouncementElement:
  def __init__(self,device,interface,prefix):
    self.device = device
    self.interface = interface
    self.prefix = prefix

  def assertInitialRibEntry(self):
    prefix_blocks = ["bl" + p for p in self.prefix.split("/")[0].split(".")]
    prefix_length = self.prefix.split("/")[1]
    pyDatalog.create_terms(",".join(prefix_blocks))
    entry_list = [self.device,self.interface,prefix_blocks[0],prefix_blocks[1],prefix_blocks[2],prefix_blocks[3],prefix_length,"nullTag","0"]
    pyDatalog.load("+(ribEntry(" + ",".join(entry_list) + "))")

###############################################################################
## Match expressions for policy clauses

class Matcher:
  def __repr__(self):
    return str(self)

  def assertMatcher(self,policyname):
    pass

class PrefixMatcher(Matcher):
  def __init__(self, prefix, mins, maxs):
    self.prefix_str = prefix
    self.min_size = int(mins)
    self.max_size = int(maxs)

  def matches(self, route):
    prefix = route.prefix.split("/")

    if not self.prefix_str == prefix[0]:
      psize = int(prefix[1])
      if psize >= self.min_size and psize <= self.max_size:
        return True

    return False

  def assertMatcher(self,policyname,clausenumber):
    prefix_blocks = ["bl" + p for p in self.prefix_str.split(".")]
    pyDatalog.create_terms(",".join(prefix_blocks))
    pyDatalog.load("+(prefixMatcher(%s,%s," % (policyname,clausenumber) + ",".join(prefix_blocks) + ",%s,%s))" % (self.min_size,self.max_size))

  def __str__(self):
    return self.prefix_str + "/[" + str(self.min_size) + "-" + str(self.max_size) + "]"

class TagMatcher(Matcher):
  def __init__(self, val):
    self.tag_value = val

  def matches(self, route):
    return route.tags.contains(self.tag_value)

  def assertMatcher(self,policyname,clausenumber):
    pyDatalog.load("+(tagMatcher(%s,%s,%s))" % (policyname,clausenumber,self.tag_value))

  def __str__(self):
    return "tag: " + self.tag_value

###############################################################################
## Actions for policy clauses

class AddTag(Action):
  def __init__(self, t):
    self.tag = t

  def apply(route):
    route.tags.add(self.tag)
    return route

  def assertMatchAction(self,policyname,clausenumber):
    pyDatalog.load("+(matchAction(%s,%s,addTag,%s))" % (policyname,clausenumber,self.tag))

  def getActionTuple(self):
    return ("addTag",self.tag)

  def __str__(self):
    return "addTag " + str(self.tag)

class RemoveTag(Action):
  def __init__(self, t):
    self.tag = t

  def apply(route):
    route.tags.discard(self.tag)
    return route

  def assertMatchAction(self,policyname,clausenumber):
    pyDatalog.load("+(matchAction(%s,%s,removeTag,%s))" % (policyname,clausenumber,self.tag))

  def getActionTuple(self):
    return ("removeTag",self.tag)

  def __str__(self):
    return "remove tag " + str(self.tag)

class Allow(Action):
  def apply(route):
    return route

  def __str__(self):
    return "allow"

  def assertMatchAction(self,policyname,clausenumber):
    pyDatalog.load("+(matchAction(%s,%s,allow,nullTag))" % (policyname,clausenumber))

  def getActionTuple(self):
    return ("allow","nullTag")

class Drop(Action):
  def apply(route):
    return None

  def __str__(self):
    return "drop"

  def getActionTuple(self):
    return ("drop","nullTag")

  def assertMatchAction(self,policyname,clausenumber):
    pyDatalog.load("+(matchAction(%s,%s,drop,nullTag))" % (policyname,clausenumber))

###############################################################################

class Clause():
  def __init__(self, m, a):
    self.matchers = m
    self.actions = a

  def matches(self, route):
    for matcher in self.matcher:
      if not matcher.matches(route):
        return False # All must match
    return True

  def apply(self, route):
    r = route
    #print r
    for action in self.actions:
      r = action.apply(r)
      if r is None:
        return None
    #print r
    return r

class Policy():
  def __init__(self, n, cls):
    self.name = n
    self.clauses = cls
    self.assertedDefaultPolicy = False
    self.assertedMatcherActions = False

  def assertPolicyInterface(self,direction,interface):
    pyDatalog.create_terms(self.name)
    pyDatalog.load("+(has%sPolicy(%s,%s))" % (direction,interface,self.name))

  def assertDefaultPolicy(self,direction):
    if not self.assertedDefaultPolicy:
      last_clause = self.clauses[-1]
      if len(last_clause.matchers) == 0:
        for a in last_clause.actions:
          pyDatalog.load("+(default%sPolicy(%s,%s,%s))" % (direction,self.name,a.getActionTuple()[0],a.getActionTuple()[1]))
      self.assertedDefaultPolicy = True

  def assertMatcherActions(self):
    if not self.assertedMatcherActions:
      for idx,c in enumerate(self.clauses):
        for m in c.matchers:
          m.assertMatcher(self.name,idx)
        for a in c.actions:
          a.assertMatchAction(self.name,idx)
      self.assertedMatcherActions = True

###############################################################################

def getTerms(network_config):
  # Fact names
  static_terms = {"neighbour", "advertisedRoute", "deviceHasInterface", "ribAnnouncements"}

  devices = set([])
  interfaces = set([])

  # Devices & Intefaces
  for device in network_config["Devices"]:
    devices.add(device["Name"])
    for interface in device["Interfaces"]:
      interfaces.add(interface["Name"].replace('@',''))
  
  return {"facts": static_terms, "devices": devices, "interfaces": interfaces}

def getInterfaces(network_config):
  facts = []
  for device in network_config["Devices"]:
    for interface in device["Interfaces"]:
      facts.append(Interface(device["Name"], interface["Name"].replace('@','')))
  return facts

def getNeighbours(network_config):
  facts = []
  for device in network_config["Devices"]:
    for interface in device["Interfaces"]:
      if not interface["Neighbor"] is None:
        facts.append(Neighbour(interface["Name"].replace('@',''), interface["Neighbor"].replace('@','')))
  return facts

def getAnnouncements(network_config):
  facts = []
  elts = []
  for device in network_config["Devices"]:
    static_routes = device["StaticRoutes"]
    advertised_routes = device["BgpConfig"][0]["AdvertisedRoutes"]
    for r in static_routes:
      if r["Prefix"] in advertised_routes:
        facts.append([device["Name"],r["Interface"].replace('@',''),r["Prefix"]])
        elts.append(AnnouncementElement(device["Name"],r["Interface"].replace('@',''),r["Prefix"]))
  return elts

def parseClauses(clauses_yaml):
  clauses = []
  for clause in clauses_yaml:
    matchers = []
    for expr in clause["Matches"]:
      pair = [e.strip() for e in expr.split(":")]
      if pair[0] == "prefix":
        expr = pair[1].split("/");
        srange = None
        if expr[1][0] == '[' and expr[1][-1] == ']':
          srange = [e.strip() for e in expr[1][1:-1].split("-")]  
        else:
          srange = [expr[1], expr[1]]
        matchers.append(PrefixMatcher(expr[0], srange[0], srange[1]))
      elif pair[0] == "tag":
        matchers.append(TagMatcher(pair[1]))
      else:
        print("NYI:", pair[0])
        exit()

    actions = []
    for action in clause["Actions"]:
      if action.startswith("add tag"):
        tag = action[7:].strip()
        actions.append(AddTag(tag))
      elif action.startswith("remove tag"):
        tag = action[10:].strip()
        actions.append(RemoveTag(tag))
      elif action == "allow":
        actions.append(Allow())
      elif action == "drop":
        actions.append(Drop())
      else:
        print("NYI:", action)
        exit()
  
    clauses.append(Clause(matchers, actions))

  return clauses

def getAllInboundPolicies(network_config):
  policies = {}
  for device in network_config["Devices"]:
    for policy in device["BgpConfig"][1]["InboundPolicies"]:
      name = policy["Name"]
      clauses = parseClauses(policy["PolicyClauses"])
      policies[policy["Name"]] = Policy(name, clauses)
  return policies

def getInboundPolicies(network_config):
  policies = {}
  for device in network_config["Devices"]:
    for policy in device["BgpConfig"][1]["InboundPolicies"]:
      name = policy["Name"]
      clauses = parseClauses(policy["PolicyClauses"])
      policies[policy["Name"]] = Policy(name, clauses)

  policy_map = {}
  for device in network_config["Devices"]:
    for interface in device["Interfaces"]:
      if not interface["InBgpPolicy"] is None:
        policy_map[interface["Name"].replace('@','')] = policies[interface["InBgpPolicy"]]

  return policy_map

def getAllOutboundPolicies(network_config):
  policies = {}
  for device in network_config["Devices"]:
    for policy in device["BgpConfig"][2]["OutboundPolicies"]:
      name = policy["Name"]
      clauses = parseClauses(policy["PolicyClauses"])
      policies[policy["Name"]] = Policy(name, clauses)
  return policies

def getOutboundPolicies(network_config):
  policies = {}
  for device in network_config["Devices"]:
    for policy in device["BgpConfig"][2]["OutboundPolicies"]:
      name = policy["Name"]
      clauses = parseClauses(policy["PolicyClauses"])
      policies[policy["Name"]] = Policy(name, clauses)

  policy_map = {}
  for device in network_config["Devices"]:
    for interface in device["Interfaces"]:
      if not interface["OutBgpPolicy"] is None:
        policy_map[interface["Name"].replace('@','')] = policies[interface["OutBgpPolicy"]]

  return policy_map

###############################################################################

def batfish(terms, interfaces, neighbours, 
              announcements, inbound_policies,  outbound_policies):
  
  
  return 1
  #print(parent(bill,X)) # prints [('John Adams',)]


###############################################################################

def match(rr, case):
  return False

def getConfig():
  network_config = open("inputs/network.yml", "r").read()
  network_config = yaml.load(network_config, Loader=yaml.FullLoader)
  return network_config

if __name__== "__main__" :
  ###############################################################################
  ## Parsing and initialization

  if len(sys.argv) != 2:
    print("Incorrect args: python batfish.py <network-file>")
    exit()

  # Load network config fule
  network_fp = sys.argv[1]
  network_config = open("inputs/network.yml", "r").read()
  network_config = yaml.load(network_config, Loader=yaml.FullLoader)
  
  # Get routing rules from batfish
  config_terms = getTerms(network_config)
  config_interfaces = getInterfaces(network_config)
  config_neighbours = getNeighbours(network_config)
  config_announcements = getAnnouncements(network_config)
  config_inbound_policies = getInboundPolicies(network_config)
  config_outbound_policies = getOutboundPolicies(network_config)

  ###############################################################################
  ## For some reason pyDatalog doesn't work inside functions, hence inlined

  # Terms to represent facts, such as neighbours
  pyDatalog.create_terms(",".join(config_terms["facts"]))

  # Terms to represent all devices and interfaces in a network
  pyDatalog.create_terms(",".join(config_terms["devices"]))
  pyDatalog.create_terms(",".join(config_terms["interfaces"]))

  # Neighbours relation between interfaces
  for n in config_neighbours:
    n.assertFact()

  # relation between device and interfaces
  for i in config_interfaces:
    i.assertFact()

  pyDatalog.create_terms("hasConnection,Device1,Interface1,Device2,Interface2,Interface3")
  hasConnection(Device1,Interface1,Interface2,Device2) <= deviceHasInterface(Device1,Interface1) & neighbour(Interface1,Interface2) & deviceHasInterface(Device2,Interface2)

  # the ultimate goal here is to build up the RIB table of all the routes each device knows
  pyDatalog.create_terms("ribEntry,nullTag")
  # using the device's static routes, we build the first layer of RIB entries
  for a in config_announcements:
    a.assertInitialRibEntry()

  # define main action types
  pyDatalog.create_terms("allow,drop,removeTag,addTag")

  pyDatalog.create_terms("hasIncomingPolicy,hasNoIncomingPolicy,defaultIncomingPolicy")
  pyDatalog.create_terms("prefixMatcher,tagMatcher,matchAction")

  for interf in config_inbound_policies.keys():
    config_inbound_policies[interf].assertPolicyInterface("Incoming",interf)
    config_inbound_policies[interf].assertDefaultPolicy("Incoming")
    config_inbound_policies[interf].assertMatcherActions()

  for i in config_terms['interfaces']:
    if i not in config_inbound_policies.keys():
      pyDatalog.load("+(hasNoIncomingPolicy(%s))" % i)

  pyDatalog.create_terms("hasOutgoingPolicy,hasNoOutgoingPolicy,defaultOutgoingPolicy")
  for interf in config_outbound_policies.keys():
    config_outbound_policies[interf].assertPolicyInterface("Outgoing",interf)
    config_outbound_policies[interf].assertDefaultPolicy("Outgoing")
    config_outbound_policies[interf].assertMatcherActions()

  for i in config_terms['interfaces']:
    if i not in config_outbound_policies.keys():
      pyDatalog.load("+(hasNoOutgoingPolicy(%s))" % i)

  def prefixLengthInRange(length,minlen,maxlen):
    return length >= minlen and length <= maxlen

  pyDatalog.create_terms("matchRouteToPrefix")
  pyDatalog.create_terms("Policyname,Clauseno,B0,B1,B2,B3,A0,A1,A2,A3,Length,Tag,Minlen,Maxlen,Cost")
  # TODO: check that route length is in matcher's range
  # Omitted: split blocks
  matchRouteToPrefix(Policyname,Clauseno,B0,B1,B2,B3,8) <= prefixMatcher(Policyname,Clauseno,B0,A1,A2,A3,Minlen,Maxlen)
  matchRouteToPrefix(Policyname,Clauseno,B0,B1,B2,B3,16) <= prefixMatcher(Policyname,Clauseno,B0,B1,A2,A3,Minlen,Maxlen)
  matchRouteToPrefix(Policyname,Clauseno,B0,B1,B2,B3,24) <= prefixMatcher(Policyname,Clauseno,B0,B1,B2,A3,Minlen,Maxlen)
  matchRouteToPrefix(Policyname,Clauseno,B0,B1,B2,B3,32) <= prefixMatcher(Policyname,Clauseno,B0,B1,B2,B3,Minlen,Maxlen)

  pyDatalog.create_terms("outgoingPolicyAllows,incomingPolicyAllows,candidateRibEntry")
  # TODO: check default policy action
  # TODO: add/remove tag actions
  outgoingPolicyAllows(Interface1,B0,B1,B2,B3,Length,Tag) <= hasNoOutgoingPolicy(Interface1)
  outgoingPolicyAllows(Interface1,B0,B1,B2,B3,Length,Tag) <= hasOutgoingPolicy(Interface1,Policyname) & matchRouteToPrefix(Policyname,Clauseno,B0,B1,B2,B3,Length) & matchAction(Policyname,Clauseno,allow,nullTag)
  outgoingPolicyAllows(Interface1,B0,B1,B2,B3,Length,Tag) <= hasOutgoingPolicy(Interface1,Policyname) & tagMatcher(Policyname,Clauseno,Tag) & matchAction(Policyname,Clauseno,allow,nullTag)

  incomingPolicyAllows(Interface1,B0,B1,B2,B3,Length,Tag) <= hasNoIncomingPolicy(Interface1)
  incomingPolicyAllows(Interface1,B0,B1,B2,B3,Length,Tag) <= hasIncomingPolicy(Interface1,Policyname) & matchRouteToPrefix(Policyname,Clauseno,B0,B1,B2,B3,Length) & matchAction(Policyname,Clauseno,allow,nullTag)
  incomingPolicyAllows(Interface1,B0,B1,B2,B3,Length,Tag) <= hasIncomingPolicy(Interface1,Policyname) & tagMatcher(Policyname,Clauseno,Tag) & matchAction(Policyname,Clauseno,allow,nullTag)

  pyDatalog.create_terms("Newcost")

  candidateRibEntry(Device2,Interface2,B0,B1,B2,B3,Length,Tag,Newcost) <= ribEntry(Device1,Interface3,B0,B1,B2,B3,Length,Tag,Cost) & hasConnection(Device1,Interface1,Interface2,Device2) & outgoingPolicyAllows(Interface1,B0,B1,B2,B3,Length,Tag) & incomingPolicyAllows(Interface2,B0,B1,B2,B3,Length,Tag) & (Newcost == Cost + 1)

  pyDatalog.create_terms("X,Y,Z,W,U,T")


  for i in range(3):
    for d,i,b0,b1,b2,b3,l,t,c in candidateRibEntry(Device2,Interface1,B0,B1,B2,B3,Length,Tag,Cost):
      cheapest = _min(candidateRibEntry(d,X,b0,b1,b2,b3,l,t,Y),order_by=Y)
      most_cheapest = sorted(cheapest, key=lambda tup: tup[0])[0]
      # do we have this route already?
      existing_entry = pyDatalog.ask("ribEntry(" + ",".join([d,"X",b0,b1,b2,b3,str(l),str(t)]) + ",Y)")
      if existing_entry is None:
        pyDatalog.load("+(ribEntry(" + ",".join([d,most_cheapest[0],b0,b1,b2,b3,str(l),str(t),str(most_cheapest[1])]) + "))")
      else:
        entry = existing_entry.answers[0]
        if most_cheapest[1] < entry[1]:
          pyDatalog.load("-(ribEntry(" + ",".join([d,entry[0],b0,b1,b2,b3,str(l),str(t),str(entry[1])]) + "))")
          for cheap in cheapest:
            pyDatalog.load("+(ribEntry(" + ",".join([d,cheap[0],b0,b1,b2,b3,str(l),str(t),str(cheap[1])]) + "))")
        if most_cheapest[1] == entry[1]:
          for cheap in cheapest:
            pyDatalog.load("+(ribEntry(" + ",".join([d,cheap[0],b0,b1,b2,b3,str(l),str(t),str(cheap[1])]) + "))")
      #  otherwise existing entry is cheaper than new entry, so do nothing

  #print(ribEntry(Device2,Interface1,B0,B1,B2,B3,Length,Tag,Cost))

  for d in sorted(config_terms['devices']):
    print("Device %s" % d)
    for i,b0,b1,b2,b3,l,t,c in ribEntry(d,Interface1,B0,B1,B2,B3,Length,Tag,Cost):
      print("%s | %s.%s.%s.%s/%s" % (i,b0[-2:],b1[-2:],b2[-2:],b3[-2:],str(l)))
