import sys
import hashlib
import jellyfish
import math
import ipaddress
from IPy import IP
import subprocess
import ConfigParser
import re
from sets import Set

from modules.db import DBops as dbops

DEBUG = False
SETTINGS_FILE = "settings.py"


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
    block_size = 65536
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
    return flag, score


def calculate_shanon_string(input):

    stList = list(input)
    alphabet = list(Set(stList)) # list of symbols in the string
    freqList = []
    for symbol in alphabet:
        ctr = 0
        for sym in stList:
            if sym == symbol:
                ctr += 1
        freqList.append(float(ctr) / len(stList))

    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        ent = ent + freq * math.log(freq, 2)
    ent = -ent

    return ent


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


def is_ipv4(input_string):
    iptocheck = unicode(input_string)
    try:
        ipaddress.IPv4Address(iptocheck)
        return True
    except Exception,e:
        return False

def valid_ip(input_string):
    #Return if IP not local/Brodacast and if private or public

    if not is_ipv4(input_string):
        return False,False

    ip_type = IP(input_string).iptype()
    if ip_type != "RESERVED" and not input_string.startswith('0.') \
            and not input_string.startswith('255.') \
            and not input_string.startswith('127.') \
            and not input_string.startswith('169.'):
        if ip_type == "PRIVATE":
            return True, "PRIVATE"
        if ip_type == "PUBLIC":
            return True, "PUBLIC"

    return False,False


def execute_volatility_plugin(plugin_type, plugin_name,
                              output, project, result,
                              shell, dump, plugin_parms, **kwargs):

    #result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}
    rc = 1
    cmd_array = []
    cmd_array.append("vol.py")
    if plugin_type == "contrib":
        cmd_array.append('--plugins='+project.get_plugins_dir())

    ##Standard vol options
    cmd_array.append('--cache')
    if project.get_volatility_profile() != "":
        cmd_array.append('--profile='+project.get_volatility_profile())
    if project.image_kdgb != "":
        cmd_array.append('--kdbg='+project.image_kdgb)
    cmd_array.append('-f')
    cmd_array.append(project.get_image_name())

    if dump:
        cmd_array.append("-D "+project.dump_dir)


    ##The actual plugin name
    cmd_array.append(plugin_name)
    if plugin_parms is not None:
        cmd_array.append(plugin_parms)

    if output == "db":
        cmd_array.append('--output=sqlite')
        cmd_array.append('--output-file='+project.db_name)

        debug(cmd_array)
        if shell:
            cmd = ' '.join(cmd_array)
            debug(cmd)
            debug("Shell enabled")
            rc = subprocess.call(cmd, shell=True)
        else:
            rc = subprocess.call(cmd_array)

        if rc == 0:
            result['status'] = True
        else:
            result['status'] = False
            result['message'] = plugin_name+" command failed!"
    if output == "stdout":
        debug(cmd_array)
        try:
            if shell:
                cmd = ' '.join(cmd_array)
                debug(cmd)
                debug("Shell enabled")
                rc = subprocess.check_output(cmd, shell=True)
            else:
                debug("Shell is not enabled")
                rc = subprocess.check_output(cmd_array)
            result['status'] = True
            result['cmd_results'] = rc
        except subprocess.CalledProcessError, e:
            result['status'] = False
            result['message'] = "Exception: "+plugin_name+" command failed!"
            result['errors'].append(e)

    return rc, result



class MafindTool():

    def test(self):
        return True

    def get_section(self, sec_number, lines, next_sec):
        return lines[sec_number:next_sec]

    def get_hex_string(self,data):
        ascii_out = []
        for i in range(4,8):
            line = data[i].split(" ")
            ascii = line[len(line)-1].strip("\n")
            ascii_out.append(ascii)

        return ascii_out

    def get_asm(self, data):
        p = re.compile(r'(^0x\w+(?:_\w+)?)+(\s\w+\S)+(\s+(\S|\s)+)')
        asm_out = []
        #print data
        for i in range(9,37):
            #line = data[i].split(" ")
            try:
                line = p.split(data[i])
                asm = line[3].strip("\n").strip(" ").replace("[","").replace("]","")
                asm_out.append(asm)
            except Exception, e:
                pass
        return asm_out

    def serialize_data(self, data):
        process_id = data[0].split(" ")[3]
        process_name = data[0].split(" ")[1]
        address = data[0].split(" ")[5].strip("\n")

        return process_id, process_name, address

    def check_mz(self, input):
        if input.startswith("MZ"):
            return True
        else:
            return False


class Project():
    '''
    Project class for all related data and methods of the project. This is
    the main class we have to load at the start of the project. It contains
    the necessary values for most of the project details such as the profile
    , directory locations, flags for features.
    It also provides several methods to provide access globally to the
    standard vars


    '''

    def __init__(self, settings_path):
        ##Everything starts from root
        self.settings_path = settings_path

        self.project_root = ""
        self.plugins_dir = ""
        self.report_export_location = ""
        self.dump_dir = ""
        self.pyplot_flag = False
        self.load_properties()
        self.db_name = ""
        self.rdb = ""
        self.volatility_profile = ""
        self.image_name = ""
        self.image_kdgb = ""

    def load_properties(self):
        '''
        Load the settings.py file

        '''
        config = ConfigParser.ConfigParser()
        config.read(SETTINGS_FILE)
        self.project_root = config.get('Directories', 'root').strip("'")
        self.plugins_dir = config.get('Directories', 'plugins').strip("'")
        self.report_export_location = config.get('Directories', 'report_export').strip("'")
        self.dump_dir = config.get('Directories', 'dump').strip("'")
        self.pyplot_flag = config.get('Graph', 'pyplot')

    def init_db(self, db_name):
        '''
        Set the DB name to be used from now on

        @db_name (str): the db name

        '''
        self.db_name = db_name
        self.rdb = dbops.DBOps(db_name)

    def clean_db(self):
        '''
        Deletes the DB

        '''
        self.rdb.clean_db(self.db_name)

    def get_root(self):
        '''
        Return the root directory of the project. This is defined in the
        settings.py file and it is mandatory

        '''
        return self.project_root

    def get_plugins_dir(self):
        '''
        Returns the plugin directory for our custom plugins

        '''
        return self.plugins_dir

    def set_volatility_profile(self, profile):
        self.volatility_profile = profile

    def get_volatility_profile(self):
        #if self.volatility_profile == "":
        #    raise ValueError("Volatility Profile not defined")
        #else:
        return self.volatility_profile

    def set_image_kdgb(self, location):
        self.image_kdgb = location

    def set_image_name(self,name):
        self.image_name = name

    def get_image_name(self):
        if self.image_name == "":
            raise ValueError("Image name is not set")
        else:
            return self.image_name


def get_a_cofee():
    '''
    While you wait, go grab a coffee!

    '''
    print('\n'
  '  ;)( ;\n'
  ' :----:\n'
  'C|====|\n'
  ' |    |\n'
  ' `----\n\n')


def check_entropy_level(sentropy):
    level = "level1"
    if float(sentropy) < 0.1:
        level = "level2"

    if float(sentropy) < 0.08:
        level = "level3"

    return level







