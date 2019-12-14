# Batfish implementation

Works with Python 3; requires the sys, yaml, and pyDatalog libraries

To run: from the batfish directory, run `python3 inputs/network.yml` The RIB tables for each device will be printed out at the command line.

## Implementation details

We implement the Batfish control plane simulator using pyDatalog. After parsing the input file, we use Datalog relations to construct a RIB table, using the main relation:
`ribEntry(Device,Interface,Block0,Block1,Block2,Block3,PrefixLength,Tag,Cost)`

To do so, we first build up our topology:

`deviceHasInterface(Device,Interface)` : links devices with their interfaces
`neighbour(Interface1,Interface2)` : links interfaces that neighbour each other

We then seed the RIB table by adding ribEntry relations for each of the network's advertised routes.

For each iteration of message passing, we construct the `candidateRibEntry` relation, for routes that have been successfully announced to a new interface. The announcement is successful when:
1. A RIB entry exists for a route on a device
2. That device is linked through one of its interfaces to a neighbouring interface
3. The device's interface allows the route to pass through its outgoing policy
4. The new interface allows the route to pass through its incoming policy

A policy allows an announcement to pass when it has no incoming/outgoing policy, or when it has a policy and when the route matches one of its clauses using either the route's prefix or its tag and when one of that clause's actions is `allow`. (Note that the add and remove tags actions are not implemented near, nor are the policy's default actions).

Once a new set of candidate RIB entries is found, we use the `min_` aggregate operator to find the device/route pairs that have the shortest distance from the device advertising the route. As long as they are not strictly greater from any routes already present in the RIB table, they are added.

The message passing process is repeated for a fixed number of iterations. Three iterations is sufficient for the example to converge.
