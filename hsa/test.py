import unittest
import sys
import yaml

from util import *
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
    self.assertEqual(rte.sym_matches(make_new_sym_header()), Header(set(['x'*32]),set(["".join(rte.prefix)]),tuple([0,1000000]),tuple([0,1000000]),tuple([0,1000000])))
    rte = RTEntry(ip_to_wce("128.0.0.0/8"),"8","test1")
    pass1 = rte.sym_matches(make_new_sym_header())
    self.assertEqual(pass1, Header(set(['x'*32]), set(["".join(ip_to_wce("128.0.0.0/8"))]),tuple([0,1000000]),tuple([0,1000000]),tuple([0,1000000])))
    rte2 = RTEntry(ip_to_wce("128.255.0.0/16"),"16","test2")
    pass2 = rte2.sym_matches(pass1)
    self.assertEqual(pass2,Header(set(['x'*32]), set(["".join(ip_to_wce("128.255.0.0/16"))]),tuple([0,1000000]),tuple([0,1000000]),tuple([0,1000000])))
    rte3 = RTEntry(ip_to_wce("70.4.182.0/24"),"24","test3")
    pass3 = rte3.sym_matches(pass2)
    self.assertEqual(pass3,Header(set(['x'*32]), set(),tuple([0,1000000]),tuple([0,1000000]),tuple([0,1000000])))
    self.assertTrue(is_empty_sym_header(pass3))

  def test_forwarding_table(self):
    forwardingtable = ForwardingTable(network_config['Devices'][0]['ForwardingTable'])
    forwardspace = forwardingtable.sym_forward(make_new_sym_header())
    # 70.4.194.22 should be forwarded to r1@Eth0
    self.assertTrue(any([hp[1] == "r1@Eth0" and e_in_wce("".join(ip_to_wce("70.4.194.22/32")),hp[0].dstIp) for hp in forwardspace]))


  def test_acl_rule(self):
    rule = Rule(network_config['Devices'][0]['Acls'][0]['Rules'][0])
    self.assertTrue(rule.matches(Header("70.4.194.22", "255.0.0.2", 5, 5, 5)))
    self.assertFalse(rule.matches(Header("70.4.4.22", "255.0.0.2", 5, 5, 5)))
    self.assertFalse(rule.matches(Header("70.4.194.22", "255.0.0.2", 10000000, 5, 5)))
    self.assertFalse(rule.matches(Header("70.4.194.22", "255.0.0.2", 5, 10000000, 5)))

  def test_sym_acl_rule(self):
    rule = Rule(network_config['Devices'][0]['Acls'][0]['Rules'][0])
    h = make_new_sym_header()
    h.srcIp = set(["".join(rule.srcIp)])
    h.dstIp = set(["".join(rule.dstIp)])
    self.assertEqual(rule.sym_matches(make_new_sym_header()), h)


  def test_acl(self):
    acl = Acl(network_config['Devices'][0]['Acls'][0])
    self.assertEqual(acl(Header("70.4.194.22", "255.0.0.2", 5, 5, 5)), "Allow")
    self.assertEqual(acl(Header("70.4.4.22", "255.0.0.2", 5, 5, 5)), "Deny")
    self.assertEqual(acl(Header("70.4.194.22", "255.0.0.2", 10000000, 5, 5)), "Deny")
    self.assertEqual(acl(Header("70.4.194.22", "255.0.0.2", 5, 10000000, 5)), "Deny")

  def test_sym_acl(self):
    acl = Acl(network_config['Devices'][0]['Acls'][0])
    allowed_sets = acl.sym_check(make_new_sym_header())
    self.assertEqual(len(allowed_sets), 1)
    self.assertEqual(allowed_sets[0].dstIp, set(['x'*32]))
    self.assertEqual(allowed_sets[0].srcIp, set(["".join(ip_to_wce("70.4.194.0/24"))]))

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

  def test_sym_transfer_function(self):
    sym_psi = TransferFunctions(network_config)
    output = sym_psi.sym_call(tuple([make_new_sym_header(),"r1@Eth1"]))

  def test_one_hop(self):
    gamma = TopologyFunction(network_config)
    psi = TransferFunctions(network_config)
    psi_output = psi(tuple([header3, "r1@Eth1"]))
    self.assertEqual(len(psi_output), 1)
    self.assertEqual(gamma(list(psi_output)[0]), set([tuple([header3, "r2@Eth1"])]))

  def test_wce_intersection(self):
    self.assertEqual(wce_intersection(set(['101x']),set(['10xx'])), set(['101x']))
    self.assertEqual(wce_intersection(set(['101x']), set(['111x'])), set())
    self.assertEqual(wce_intersection(set(['xxxx']), set(['11xx'])), set(['11xx']))

  def test_wce_union(self):
    self.assertEqual(wce_union(set(['01xx']), set(['111x'])), set(['01xx', '111x']))

  def test_wce_complement(self):
    self.assertEqual(wce_complement(set(['01x'])), set(['1xx','x0x']))
    self.assertEqual(wce_complement(set()), set(['x' * 32]))
    self.assertEqual(wce_complement(set(['x' * 32])), set())

if __name__ == '__main__':
  unittest.main()