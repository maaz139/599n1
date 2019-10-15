class network_transfer_function:
  '''
  A class implementing a network transfer function.
  '''

  def __init__(self, fn):
    self.ntf = fn
    
  def __call__(self, header, port):
    fn()