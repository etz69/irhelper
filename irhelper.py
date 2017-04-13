import pickle
import argparse
from jinja2 import Environment, FileSystemLoader
import ConfigParser

from modules.db.ops import *
from modules import cmd_processor

GLOBALS = {}
GLOBALS['_VOLATILITY_PROFILE'] = ""
GLOBALS['_KDBG'] = ""
GLOBALS['_cache'] = True
GLOBALS['PLUGIN_DIR'] = sys.path[0]+"/vol_plugins/"
GLOBALS['DUMP_DIR'] = sys.path[0]+"/dump/"
CACHE_FILE = "/tmp/memoize.pkl"
DB_NAME = "results.db"
SETTINGS_FILE = "settings.py"

_VOLATILITY_LOCATION = ""


parser = argparse.ArgumentParser(prog="irhelper.py",
                                 formatter_class =
                                 argparse.RawDescriptionHelpFormatter,
                                 description='\n'
  '  ;)( ;\n'
  ' :----:\n'
  'C|====|\n'
  ' |    |\n'
  ' `----\n\n'
                                'The IR helper python tool!')

#Required arguments
parser.add_argument("reportTemplate", type=str,
                    help='Report template to use')
parser.add_argument("memoryImageFile", type=str,
                    help="The memory image file you want to analyse")

parser.add_argument("-p", '--profile', nargs='?', help="Volatility profile")
parser.add_argument('--cache', action="store_true", help="Enable cache")
parser.add_argument('--debug', action="store_true", help="Run in debug")
parser.add_argument('--initdb', action="store_true", help="Initialise local DB")
parser.add_argument('--hash',action="store_true", help="Generate hashes")
parser.add_argument("-v", '--version', action="version",
                    version="%(prog)s v0.1.0")

args = parser.parse_args()

from functools import wraps
def memoize(func):
    if os.path.exists(CACHE_FILE) and args.cache:
        print 'Using local cache ..'
        with open(CACHE_FILE) as f:
            cache = pickle.load(f)
    else:
        cache = {}
    @wraps(func)
    def wrap(*args):
        if args not in cache:
            print 'No cache, normal run'
            cache[args] = func(*args)
            if cache[args]['status']:
                # update the cache file
                with open(CACHE_FILE, 'wb') as f:
                    pickle.dump(cache, f)
            else:
                pass
        else:
            debug("Loading results from cache")
            print(args)
        return cache[args]
    return wrap


@memoize
def run_cmd(command, target_file):

    cmdp = cmd_processor.CommandProcessor()
    #print("\nSupported Commands:")
    #for cmd in cmdp.get_commands():
    #    print cmd
    debug("Running cmd: %s" %command)
    response = cmdp.prep_cmd(command, target_file, GLOBALS)
    if not response['status']:
        err(response['message'])
    else:
        response = cmdp.get_result()
    if not response['status']:
        err("Command %s failed. Will not cache results" %command)
    return response


def main():

    ##Load settings.py
    config = ConfigParser.ConfigParser()
    config.read(SETTINGS_FILE)
    global GLOBALS
    GLOBALS['PLUGIN_DIR'] = config.get('Directories', 'plugins').strip("'")

    ##Initialise our database
    rdb = DBOps(DB_NAME)

    if args.debug:
        set_debug(True)
    if args.initdb:
        rdb.clean_db(DB_NAME)

    if not os.path.isfile(args.reportTemplate):
        print("ERROR: Report template not found: %s" % args.reportTemplate)
        return
    if not os.path.isfile(args.memoryImageFile):
        print("ERROR: Memory image file not found: %s" % args.memoryImageFile)
        return
    if args.profile:
        GLOBALS['_VOLATILITY_PROFILE'] = args.profile
        debug("Using %s" %GLOBALS['_VOLATILITY_PROFILE'])
    else:
        print("No profile provided")

    if args.hash:
        md5 = md5sum(args.memoryImageFile)
        debug("MD5:%s" %md5)
    else:
        md5 = "NONE"

    response = run_cmd("vol_imageinfo", args.memoryImageFile)

    if not response['status']:
        err(response['message'])
        exit()

    image_info = response['cmd_results']
    print_cmd_results(image_info)

    ##Set global target image values
    GLOBALS['_KDBG'] = image_info['KDBG']
    image_info['image_name'] = args.memoryImageFile
    profile_array = image_info['Suggested Profile(s)'].split(",")

    if GLOBALS['_VOLATILITY_PROFILE'] == "":
        for n in range(0, len(profile_array)):
            print("%s) %s" %(n,profile_array[n].strip()))
        print("If you see only profile names then select a number. If not use the full word")
        choice = raw_input("Please enter profile number or name: ")
        try:
            profile = profile_array[int(choice)].strip()
        except Exception,e:
            profile = choice

        GLOBALS['_VOLATILITY_PROFILE'] = profile
    else:
        profile = GLOBALS['_VOLATILITY_PROFILE']


    print("\nWill be using profile: %s" % profile)

    ##### Basic image info retrieved #####

    response = run_cmd("vol_getosversion",args.memoryImageFile)

    if not response['status']:
        err(response['message'])
        version_info = "{}"
    else:
        version_info = response['cmd_results']

    response = run_cmd("vol_netscan", args.memoryImageFile)
    if not response['status']:
        err(response['message'])

    response = run_cmd("vol_pslist", args.memoryImageFile)
    if not response['status']:
        err(response['message'])
    rule_violations = response['cmd_results']

    response = run_cmd("vol_regdump", args.memoryImageFile)
    if not response['status']:
        err(response['message'])
    user_info = response['cmd_results']

    ##Write to template
    if not os.path.exists("export"):
        os.makedirs("export")

    exportpath = "export/{}".format(args.reportTemplate.split("/")[1])
    fo = open(exportpath, "w")

    env = Environment(loader=FileSystemLoader("./"), trim_blocks=True)
    print("Violations: %s" %len(rule_violations))
    mytemplate = env.get_template(args.reportTemplate).render(
        profiles=",".join(profile_array),
        image_info=image_info,
        image_md5=md5,
        version_info=version_info,
        rule_violations=rule_violations,
        users=user_info
    )
    debug("Writing report ..")
    fo.write(mytemplate.encode('utf-8'))
    fo.close

if __name__ == "__main__":
    main()

