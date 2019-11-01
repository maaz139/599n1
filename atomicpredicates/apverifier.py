# limitations
# apverifier paper only considers IP networks

from pyeda.inter import *

# returns bdd that represents whether an entry in ACL table matches a (generic) header
def ACL_line_to_bdd(acl):
  pass

# Yang & Lam 2013 algorithm 1
# shouldn't there be a cleanup line for the default action?
def ACLs_to_predicate(acls):
  allowed = expr2bdd(expr(False))
  denied = expr2bdd(expr(False))
  for acl in acls:
    if acl.action == "deny":
      denied = denied | (ACL_line_to_bdd(acl) & (~ denied))
    else
      allowed = allowed | (ACL_line_to_bdd(acl) & (~ denied))
  return allowed

# represent forwarding table prefix as a bdd
def prefix_to_bdd(prefix):
  pass

# Yang & Lam 2013 algorithm 2
# assumed ft is sorted
def forwardingtable_to_predicate(ft, ports):
  predicates = [expr2bdd(expr(False)) for p in ports]
  fwd = expr2bdd(expr(False))
  for ft_entry in ft:
    # find the port idx for the port in the ft entry
    p_idx = 0
    predicates[p_idx] = predicates[p_idx] | (prefix_to_bdd(ft_entry.prefix) & (~ fwd))
    fwd = fwd | prefix_to_bdd(ft_entry.prefix)
  return predicates

def get_atomic_pred_from_predicate(p):
  if is_one(p):
    return [expr2bdd(expr(True))]
  elif is_zero(p):
    return [expr2bdd(expr(False))]
  else:
    return [p, ~ p]

def atomic_predicate_intersection(ap1, ap2):
  intersection = []
  for p1 in ap1:
    for p2 in ap2:
      if not is_zero(p1 & p2):
        intersection.append(p1 & p2)
  return intersection

# Yang & Lam 2013 algorithm 3
def compute_atomic_predicates(predicates):
  self_atomic_preds = [get_atomic_pred_from_predicate(p) for p in predicates]
  atomic_preds = [self_atomic_preds[0]]
  running_predicate = self_atomic_preds[0]
  for i in range(1,len(predicates)):
    running_predicate = atomic_predicate_intersection(running_predicate, self_atomic_preds[i])
    atomic_preds[i] = running_predicate
  return running_predicate

# one path is a list of ports that connects port1 and port2 inclusive
# this method returns a list of all such paths in the network
def get_paths(port1, port2):
  pass

# return the atomic predicates for forwarding through a port
def get_ap_forwarding_by_port(port):
  pass

# return the atomic predicates for ACLs by port
def get_ap_acls_by_port(port):
  pass

def path_reachability(path):
  forwarding_path_ap = [get_ap_forwarding_by_port(p) for p in path]
  acls_ap = [get_ap_acls_by_port(p) for p in path]
  forwarding_intersection = compute_atomic_predicates(forwarding_path_ap)
  if is_zero(forwarding_intersection):
    return expr2bdd(expr(False))
  acls_intersection = compute_atomic_predicates(acls_ap)
  if is_zero(acls_intersection):
    return expr2bdd(expr(False))
  return tuple([forwarding_intersection,acls_intersection])
