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

# repeat this until the size of rib_entry doesn't change
for d1,d2,rte in advertiseRound(Device1,Device2,Route):
  +(rib_entry(d1,d2,rte))
