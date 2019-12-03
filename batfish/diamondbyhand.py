from pyDatalog import pyDatalog

# datalog for the diamond network by hand

# interfaces are terms
pyDatalog.create_terms('r1Eth0,r1Eth1,r1Eth2,r2Eth1,r2Eth2,r3Eth1,r3Eth2,r4Loopback0,r4Eth3,r4Eth1,r4Eth2')
pyDatalog.create_terms('neighbours')

# neighbours relation between interfaces
+(neighbours(r1Eth1,r2Eth1))
+(neighbours(r1Eth2,r3Eth1))
+(neighbours(r2Eth1,r1Eth1))
+(neighbours(r2Eth2,r4Eth1))
+(neighbours(r3Eth1,r1Eth2))
+(neighbours(r3Eth2,r4Eth2))
+(neighbours(r4Eth1,r2Eth2))
+(neighbours(r4Eth2,r3Eth2))

pyDatalog.create_terms('r1,r2,r3,r4')
pyDatalog.create_terms('deviceHasInterface')

# associate devices with their interfaces
+(deviceHasInterface(r1,r1Eth0))
+(deviceHasInterface(r1,r1Eth1))
+(deviceHasInterface(r1,r1Eth2))
+(deviceHasInterface(r2,r2Eth1))
+(deviceHasInterface(r2,r2Eth2))
+(deviceHasInterface(r3,r3Eth1))
+(deviceHasInterface(r3,r3Eth2))
+(deviceHasInterface(r4,r4Loopback0))
+(deviceHasInterface(r4,r4Eth1))
+(deviceHasInterface(r4,r4Eth1))
+(deviceHasInterface(r4,r4Eth2))
+(deviceHasInterface(r4,r4Eth3))

# let ip1 = 70.4.194.0/24
# let ip2 = 70.4.193.0/24
# let ip3 = 10.0.0.1/32
pyDatalog.create_terms('ip1,ip2,ip3')
pyDatalog.create_terms('deviceAdvertisedRoutes')

# these are the routes each device initially advertises
+(deviceAdvertisedRoutes(r1,ip1))
+(deviceAdvertisedRoutes(r4,ip2))
+(deviceAdvertisedRoutes(r4,ip3))

pyDatalog.create_terms('Device1,Device2,Device3,Device4,Route,Interface1,Interface2')
pyDatalog.create_terms('topologyConnection')
pyDatalog.create_terms('advertiseSeedRound')
pyDatalog.create_terms('rib_entry')

# calculate devices that are connected to each other
topologyConnection(Device1,Device2) <= deviceHasInterface(Device1,Interface1) & deviceHasInterface(Device2,Interface2) & neighbours(Interface1,Interface2)

# find the routes initially advertised by devices to their immediate neighbors
advertiseSeedRound(Device1,Device2,Route) <= topologyConnection(Device1,Device2) & deviceAdvertisedRoutes(Device1,Route)

# put these in the RIB entry relation
for d1,d2,rte in advertiseSeedRound(Device1,Device2,Route):
  +(rib_entry(d1,d2,rte))

pyDatalog.create_terms('advertiseRound')

# execute one round of advertising the routes the devices currently know about
advertiseRound(Device1,Device2,Route) <= topologyConnection(Device1,Device2) & rib_entry(Device3,Device1,Route)

# if we only advertised routes without any other filters:
# repeat this until the size of rib_entry doesn't change
# for d1,d2,rte in advertiseRound(Device1,Device2,Route):
#  +(rib_entry(d1,d2,rte))

# now let's consider policies
pyDatalog.create_terms('rib_candidate')
pyDatalog.create_terms('outbound_policies,inbound_policies')
pyDatalog.create_terms('policy_prefix_actions,policy_tag_actions,default_policy_actions')
pyDatalog.create_terms('r1_default_bgp_export,prefix1,prefix2,prefix3,add,remove,tag1,nulltag,allow,drop')
pyDatalog.create_terms('r4_default_bgp_import')
pyDatalog.create_terms('Policyname1,Policyname2,Prefix1,Prefix2')

+(outbound_policies(r1,r1_default_bgp_export)
+(policy_prefix_actions(r1_default_bgp_export,prefix1,allow))
+(policy_tag_actions(r1_default_bgp_export,tag1,allow))
+(default_policy_actions(r1_default_bgp_export,drop))
+(inbound_policies(r4,r4_default_bgp_import,prefix2))

# use python impl of prefix matching here
def match(ip,prefix):
  pass

pyDatalog.create_terms('match')
pyDatalog.create_terms('allow_outbound_policy,allow_inbound_policy')

allow_outbound_policy(Interface1,Route) <= outbound_policies(Interface1,Policyname1) & default_policy_actions(Policyname1,allow)
allow_outbound_policy(Interface1,Route) <= outbound_policies(Interface1,Policyname1) & policy_prefix_actions(Policyname1,Prefix1,allow) & match(Route,Prefix1)
# if an interface doesn't have a specified policy, default is to allow
allow_outbound_policy(Interface1,Route) <= len_(outbound_policies(Interface1,Policyname1)) == 0

allow_inbound_policy(Interface1,Route) <= inbound_policies(Interface1,Policyname1) & default_policy_actions(Policyname1,allow)
allow_inbound_policy(Interface1,Route) <= inbound_policies(Interface1,Policyname1) & policy_prefix_actions(Policyname1,Prefix1,allow) & match(Route,Prefix1)
allow_inbound_policy(Interface1,Route) <= len_(inbound_policies(Interface1,Policyname1)) == 0
# should also be a way to match on tag

rib_candidate(Device1,Device2,Route) <= deviceHasInterface(Device1,Interface1) & deviceHasInterface(Device2,Interface2) & neighbours(Interface1,Interface2) & advertiseRound(Device1,Device2,Route) & allow_outbound_policy(Interface1,Route) & allow_inbound_policy(Interface1,Route)

# find all solutions for rib_candidate and add them as facts to rib_entry

# TODO: if we find more than one RIB entry for Device1 and Route, need to pick one

# TODO: handle tags 
# need a version of rib_candidate that matches on tags, not prefixes
# are tags always added in outbound and removed in inbound? Or should they be stored in RIB?

# TODO: add a cost measure to RIB, probably # of hops
# if a route with better cost is found, old route is removed from RIB and new route added
# remove a fact from the global store like this:
# -(rib_entry(x,y,z))
