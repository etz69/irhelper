import sys
import hashlib
import jellyfish


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


def set_debug(bool):

    global DEBUG
    DEBUG = bool


def md5sum(filename):
    blocksize=65536
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

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


