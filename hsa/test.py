import unittest
import sys
import yaml

from util import Header, Rule, Acl, RTEntry, ForwardingTable, ip_to_wce
from hsa import TopologyFunction, TransferFunctions

network_config = open("network.yml", "r").read();
network_config = yaml.load(network_config, Loader=yaml.FullLoader)

header1 = Header("70.4.194.22", "255.0.0.2", 5, 5, 5)
header2 = Header("255.0.0.1", "70.4.193.0", 5, 5, 5)
header3 = Header("70.4.194.182", "10.0.0.1", 5, 5, 5)

class TestUtil(unittest.TestCase):

  def test_topology(self):
    gamma = TopologyFunction(network_config)
    # dummy header object since we only care about toplogy
    self.assertEqual(gamma(tuple(["h","r2@Eth2"])), set([tuple(["h", "r4@Eth1"])]))
    self.assertEqual(gamma(tuple(["h","r4@Loopback0"])), set())

  def test_routing_table_entry(self):
    rte = RTEntry(ip_to_wce("70.4.193.0/24"), "24", "r4:Eth3")
    self.assertTrue(rte.matches(header2))

  def test_forwarding_table(self):
    forwardingtable = ForwardingTable(network_config['Devices'][0]['ForwardingTable'])
    self.assertTrue(forwardingtable(header2), set("r1@Eth0"))

  def test_acl_rule(self):
    rule = Rule(network_config['Devices'][0]['Acls'][0]['Rules'][0])
    self.assertTrue(rule.matches(Header("70.4.194.22", "255.0.0.2", 5, 5, 5)))
    self.assertFalse(rule.matches(Header("70.4.4.22", "255.0.0.2", 5, 5, 5)))
    self.assertFalse(rule.matches(Header("70.4.194.22", "255.0.0.2", 10000000, 5, 5)))
    self.assertFalse(rule.matches(Header("70.4.194.22", "255.0.0.2", 5, 10000000, 5)))

  def test_acl(self):
    acl = Acl(network_config['Devices'][0]['Acls'][0])
    self.assertEqual(acl(Header("70.4.194.22", "255.0.0.2", 5, 5, 5)), "Allow")
    self.assertEqual(acl(Header("70.4.4.22", "255.0.0.2", 5, 5, 5)), "Deny")
    self.assertEqual(acl(Header("70.4.194.22", "255.0.0.2", 10000000, 5, 5)), "Deny")
    self.assertEqual(acl(Header("70.4.194.22", "255.0.0.2", 5, 10000000, 5)), "Deny")

  def test_transfer_function(self):
    psi = TransferFunctions(network_config)
    self.assertEqual(psi.check_outbound_acl(Header("70.4.194.22", "255.0.0.2", 5, 5, 5), "r1@Eth2"), "Allow")
    self.assertEqual(psi.check_outbound_acl(Header("70.4.4.22", "255.0.0.2", 5, 5, 5), "r1@Eth2"), "Deny")
    self.assertEqual(psi.check_outbound_acl(Header("70.4.194.22", "255.0.0.2", 10000000, 5, 5), "r1@Eth2"), "Deny")
    self.assertEqual(psi.check_outbound_acl(Header("70.4.194.22", "255.0.0.2", 5, 10000000, 5), "r1@Eth2"), "Deny")
    self.assertEqual(psi.routingTable["r1@Eth2"](header2), set(["r1@Eth1"]))

    self.assertEqual(psi.check_inbound_acl(header3, "r1@Eth1"), "Allow")
    self.assertEqual(psi.routingTable["r1@Eth1"](header3), set(["r1@Eth1"]))
    self.assertEqual(psi.check_outbound_acl(header3, "r1@Eth1"), "Allow")
    self.assertEqual(psi(tuple([header3,"r1@Eth1"])), set([tuple([header3,"r1@Eth1"])]))

  def test_one_hop(self):
    gamma = TopologyFunction(network_config)
    psi = TransferFunctions(network_config)
    psi_output = psi(tuple([header3, "r1@Eth1"]))
    self.assertEqual(len(psi_output), 1)
    self.assertEqual(gamma(list(psi_output)[0]), set([tuple([header3, "r2@Eth1"])]))

  def test_wce_intersection(self):
    self.assertEqual(wce_intersection(['101x'],['10xx']), list(['101x']))
    self.assertEqual(wce_intersection(['101x'], ['111x']), list())

  def test_wce_union(self):
    self.assertEqual(wce_union(['01xx'], ['111x']), ['01xx', '111x'])

  def test_wce_complement(self):
    self.assertEqual(wce_complement(['01x']), ['1xx','x0x'])

if __name__ == '__main__':
  unittest.main()