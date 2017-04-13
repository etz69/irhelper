import sys
import hashlib
import jellyfish
import math

DEBUG = False


def debug(msg):
    '''
    Single entry point for printing debug messages to stdout.

    @msg: the debug string to print
    '''

    if DEBUG:
        sys.stderr.write("DEBUG: %s\n" % msg)
        sys.stderr.flush()


def err(msg):
    sys.stderr.write("ERROR: %s\n" % msg)


def set_debug(flag):

    global DEBUG
    DEBUG = flag


def md5sum(filename):
    block_size=65536
    _hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            _hash.update(block)
    return _hash.hexdigest()


def print_header(msg):
    print("\n-------------------------------------")
    print(msg)
    print("-------------------------------------\n")


def print_cmd_results(data):
    print("\n-------------------------------------")
    for k in data:
        print("%s: %s" %(k, data[k]))
    print("-------------------------------------\n")


def score_jaro_distance(string1, string2):
    threshold = float(0.90)
    flag = False
    score = jellyfish.jaro_distance(unicode(string1),unicode(string2))
    if score > threshold:
        flag = True
    return flag,score

##Dirty implementation to get binary file entropy
##https://github.com/tripleee/entro.py/blob/master/entro.py
##Not as good as DensityScout

class Bit (str):
    def __iter__ (self):
        for i in xrange(str.__len__(self)):
                for b in xrange(8):
                    yield chr((ord(self[i])&(2**b)) >> b)

    def __len__(self):
        return str.__len__(self) * 8

    def width(self, member):
        return 2


def calculate_shanon_entropy_file(file_path):
    handle = open(file_path)
    data = Bit(handle.read())
    return round(binary_shanon_entropy(data), 5)


def binary_shanon_entropy(data, _debug=False):
    entropy = 0
    count = dict()
    for c in data:
        try:
            count[c] += 1
        except KeyError:
            count[c] = 1
    for x in count:
        p_x = float(count[x])/len(data)
        if _debug:
            print "# %r: p_x=%i/%i=%f; -p_x*log(p_x,%i)=%f; sum = %f" % (
                x, count[x], len(data), p_x, data.width(x),
                -p_x*math.log(p_x, data.width(x)),
                entropy - (p_x * math.log(p_x, data.width(x))))
        ######## FIXME: base should be 8 for byte entropy,
        # but unclear what exactly it should be for UTF-8
        entropy += - p_x*math.log(p_x, data.width(x))
    return entropy

