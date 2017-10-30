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
import glob
import os
import requests
import json
from time import sleep

sys.path.append(sys.path[0]+"/../../")
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

def sha1sum(filename):
    block_size = 65536
    _hash = hashlib.sha1()
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
        print("%s: %s" % (k, data[k]))
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

    return False, False


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

        cmd = ' '.join(cmd_array)
        debug(cmd)
        if shell:
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
        cmd = ' '.join(cmd_array)
        debug(cmd)
        try:
            if shell:
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


class HollowfindTool():

    def test(self):
        return True

    def parse_output(self, data):
        ##dirty data extraction routine. Sqlite output is broken
        results = list()
        pinfo_hollow = dict()

        count = 0
        _outlength = 8
        hfound = False
        for line in data:
            l = line.strip("\n\t")
            if l == "Hollowed Process Information:" or hfound:
                if count == 1:
                    pinfo_hollow['pname'] = l.split(" ")[1]
                if count == 1:
                    pinfo_hollow['pid'] = l.split(" ")[3]
                if count == 3:
                    pinfo_hollow['date'] = l.split(" ")[2]
                if count == 6:
                    pinfo_hollow['description'] = l
                hfound = True
                count+=1

                if count == _outlength:
                    hfound = False
                    count = 0
                    results.append(pinfo_hollow.copy())
        return results


class MafindTool():

    def test(self):
        return True

    def get_section(self, sec_number, lines, next_sec):
        return lines[sec_number:next_sec]

    def get_hex_string(self, data):
        ascii_out = []
        for i in range(4,8):
            line = data[i].split(" ")
            ascii = line[len(line)-1].strip("\n")
            ascii_out.append(ascii)

        return ascii_out

    def get_asm(self, data):
        p = re.compile(r'(^0x\w+(?:_\w+)?)+(\s\w+\S)+(\s+(\S|\s)+)')
        asm_out = []
        for i in range(9,37):
            try:
                line = p.split(data[i])
                asm = line[3].strip("\n").strip(" ").replace("[","").replace("]","")
                asm_out.append(asm)
            except Exception, e:
                pass
        return asm_out

    def serialize_dataORIG(self, data):
        process_id = data[0].split(" ")[3]
        process_name = data[0].split(" ")[1]
        address = data[0].split(" ")[5].strip("\n")

    def serialize_data(self, data):
        l = data[0].split(" ")
        process_id = l[l.index('Pid:')+1]
        process_name = l[l.index('Process:')+1]
        address = l[l.index('Address:')+1].strip("\n")

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
        self.db_name = ""
        self.rdb = ""
        self.volatility_profile = ""
        self.image_name = ""
        self.image_kdgb = ""
        self.result = self.init_result()
        self.load_properties(self)

    @staticmethod
    def init_result():
        _result = dict()
        _result['status'] = True
        _result['messages'] = []
        _result['cmd_results'] = ''
        _result['errors'] = []
        _result['findings'] = []
        return _result

    @staticmethod
    def load_properties(self):
        '''
        Load the settings.py file

        '''
        config = ConfigParser.ConfigParser()
        config.read(SETTINGS_FILE)
        self.project_root = config.get('Directories', 'root').strip("'")
        self.plugins_dir = config.get('Directories', 'plugins').strip("'")
        self.report_export_location = config.get('Directories',
                                                 'report_export').strip("'")
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
        Deletes the DB, cache and all files from dump dir

        '''
        files_to_delete = glob.glob(self.dump_dir+"*")
        self.rdb.clean_db(self.db_name)

        cache_file = "/tmp/memoize.pkl"
        try:
            os.remove(cache_file)
        except Exception as e:
            pass

        if len(files_to_delete) > 0:
            print("I am about to delete [%d] files "
                  "from: [%s] and erase the DB" % (len(files_to_delete), self.dump_dir))
            choice = raw_input("Confirm [y/n]")

            if choice == "n":
                return
            if choice == "y":
                for f in files_to_delete:
                    os.remove(f)

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


def calculate_risk(risk_index, process_info, plist, risk_level):
    list_of_suspicious_processes = list()
    suspicious_process = dict()

    rdict = dict()
    for el in risk_index:
        if type(el) == list:
            for e in el:
                if e['pid'] in rdict:
                    rdict[e['pid']] = rdict[e['pid']]+e['risk']
                else:
                    rdict[e['pid']] = e['risk']
        else:
            if el['pid'] in rdict:
                rdict[el['pid']] = rdict[el['pid']]+el['risk']
            else:
                rdict[el['pid']] = el['risk']

    if risk_level is None:
        print("User Risk level is none. Defaulting to L2 and above ")
    pextended = True
    if len(process_info) == 0:
        pextended = False
        process_info = plist

    for risk_process in rdict:
        for process in process_info:
            if str(process['pid']) == str(risk_process):
                suspicious_process['pid'] = risk_process
                if pextended:
                    suspicious_process['name'] = process['process_name']
                    suspicious_process['md5'] = process['md5']
                else:
                    suspicious_process['name'] = process['name']
                    suspicious_process['md5'] = "-"


                suspicious_process['risk_index'] = rdict[risk_process]
                if risk_level is None:
                    if int(suspicious_process['risk_index']) >= 2:
                        list_of_suspicious_processes.append(suspicious_process.copy())
                else:
                    if int(suspicious_process['risk_index']) >= int(risk_level):
                        list_of_suspicious_processes.append(suspicious_process.copy())

    return list_of_suspicious_processes


def get_cifapp_info(data):

    session = requests.Session()
    indicators = list()
    config = ConfigParser.ConfigParser()
    try:
        config.read(SETTINGS_FILE)
        API_KEY = config.get('c1fapp', 'C1F_API_KEY').strip("'")
        API_URL = config.get('c1fapp', 'C1F_API_URL').strip("'")
    except Exception as e:
        err("No C1F Key found")
        sys.exit(1)

    for entry in data:
        indicator_report = dict()

        if entry['address_type'] == "PUBLIC":
            print(entry)
            payload = {'key': API_KEY,
                       'format': 'json',
                       'backend': 'es',
                       'request': entry['ip_address']
            }

            indicator_report['found'] = False
            indicator_report['country'] = ""

            countries = list()
            c1fapp_query = session.post(API_URL, data=json.dumps(payload))

            try:
                results = json.loads(c1fapp_query.text)

                if len(results) > 0:
                    indicator_report['found'] = True

                    for i in results:
                        if "country" in i:
                            countries.append(i['country'][0])

            except ValueError:
                print("No JSON object could be decoded.")

            if indicator_report['found'] and len(countries) > 0:
                indicator_report['countries'] = list(set(countries)[0])

            entry['indicator_report'] = indicator_report.copy()
            indicators.append(entry)
        else:
            indicator_report['found'] = False
            indicator_report['country'] = ""
            entry['indicator_report'] = indicator_report.copy()
            indicators.append(entry)

    return indicators


def check_hash_vt(risk_list, check):

    enhanced_risk_list = list()

    if not check:
        for entry in risk_list:
            entry['vt_code'] = 0
            entry['positives'] = 0
            entry['total'] = 0
            entry['permalink'] = ""
            enhanced_risk_list.append(entry.copy())

        return enhanced_risk_list

    config = ConfigParser.ConfigParser()
    config.read(SETTINGS_FILE)
    try:
        config.read(SETTINGS_FILE)
        VT_API_KEY = config.get('virustotal', 'VT_API_KEY').strip("'")
        VT_FILE_API_URL = config.get('virustotal', 'VT_FILE_API_URL').strip("'")
        VT_API_TYPE = config.get('virustotal', 'VT_API_TYPE').strip("'")
    except Exception as e:
        err("No VT Key found")
        sys.exit(1)

    session = requests.Session()
    count = int(len(risk_list))
    if VT_API_TYPE == 'public':
        print("*** VT KEY is public. Applying 25 sec throttling! ***")
        time_elapsed_public = (int(count)*25)/60
        print("*** This will take approximately [%d] minutes     ***" %time_elapsed_public)

    for entry in risk_list:
        if entry['md5'] != "-":
            params = {'apikey': VT_API_KEY, 'resource': entry['md5']}
            headers = {
              "Accept-Encoding": "gzip, deflate",
              "User-Agent" : "Python iRhelper agent"
              }
            try:
                vt_query = session.get(VT_FILE_API_URL, params=params,
                                       headers= headers)
                results = json.loads(vt_query.text)
                if VT_API_TYPE == 'public':
                    sleep(25)
                if results['response_code'] == 1:
                    entry['vt_code'] = 1
                    entry['positives'] = results['positives']
                    entry['total'] = results['total']
                    entry['permalink'] = results['permalink']
                    enhanced_risk_list.append(entry.copy())
                else:
                    entry['vt_code'] = 0
                    entry['positives'] = 0
                    entry['total'] = 0
                    entry['permalink'] = ""
                    enhanced_risk_list.append(entry.copy())

            except ValueError:
                print("No JSON object could be decoded.")
                entry['vt_code'] = 0
                entry['positives'] = 0
                entry['total'] = 0
                entry['permalink'] = ""
                enhanced_risk_list.append(entry.copy())
        else:
            entry['vt_code'] = 0
            entry['positives'] = 0
            entry['total'] = 0
            entry['permalink'] = ""
            enhanced_risk_list.append(entry.copy())


    return enhanced_risk_list



def sqlite_to_es(db_file):
    ##Get all the tables
    ##SELECT name FROM sqlite_master WHERE type='table';

    #for every table read all data and transform to dict with
    #  keys from column names
    ## We can use DBops.sqlite_query_to_json(query) for this

    pass



if __name__ == "__main__":

    DB_NAME = "results.db"

    set_debug(True)
    import sqlite3

    ##Call the actual command
    current_wd = sys.path[0]
    my_project = Project(current_wd)
    my_project.init_db(DB_NAME)

    rdb = dbops.DBOps(my_project.db_name)
    conn = sqlite3.connect(my_project.db_name)

    sql = 'SELECT name FROM sqlite_master WHERE type="table"'

    c = conn.cursor()
    c.row_factory = sqlite3.Row
    c.execute(sql)

    tables = c.fetchall()

    for table in tables:
        print(table[0])

    results = rdb.sqlite_query_to_json("select * from SystemInfo")
    print(json.dumps(results, sort_keys=False, indent=4))






