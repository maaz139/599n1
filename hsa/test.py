import unittest
import sys
import yaml

from util import RTEntry, ForwardingTable, ip_to_wce
from hsa import TopologyFunction

network_config = open("network.yml", "r").read();
network_config = yaml.load(network_config, Loader=yaml.FullLoader)

class TestUtil(unittest.TestCase):

  def test_topology(self):
    gamma = TopologyFunction(network_config)
    # dummy header object for now
    self.assertEqual(gamma("h","r2@Eth2"), set([tuple(["h", "r4@Eth1"])]))
    self.assertEqual(gamma("h","r4@Loopback0"), set())

  def test_routing_table_entry(self):
    rte = RTEntry(ip_to_wce("70.4.193.0/24"), "24", "r4:Eth3")
    header_dst_ip = "70.4.193.10"
    self.assertTrue(rte.matches(header_dst_ip))

  def test_forwarding_table(self):
    forwardingtable = ForwardingTable(network_config['Devices'][0]['ForwardingTable'])
    self.assertTrue(forwardingtable("70.4.194.22"), set("r1@Eth0"))

if __name__ == '__main__':
  unittest.main()