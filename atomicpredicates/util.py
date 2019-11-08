from pyeda.inter import *

# take a string representing an IP address and a prefix
# return a BDD representing a predicate that is true when that IP address is matched
def ipaddress2bdd(ip_str, packet_ip):
  prefix_length = int(ip_str.split("/")[1])
  prefix = ip_str.split("/")[0]

  binary_string_prefix = ''.join([bin(int(x)+256)[3:] for x in prefix.split('.')])

  # initialize as true, since 0.0.0.0/0 becomes True
  ip_bdd = expr2bdd(expr(1))

  for i in range(prefix_length):
    if binary_string_prefix[i] == '1':
      ip_bdd = ip_bdd & packet_ip[i]
    else:
      ip_bdd = ip_bdd & ~ packet_ip[i]

  return ip_bdd