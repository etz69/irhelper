import pickle
import argparse
from jinja2 import Environment, FileSystemLoader


from modules import cmd_processor
from modules.utils.helper import *
import sys
import os

GLOBALS = {}

GLOBALS['_KDBG'] = ""
GLOBALS['_cache'] = True
#GLOBALS['PLUGIN_DIR'] = sys.path[0]+"/vol_plugins/"
#GLOBALS['DUMP_DIR'] = sys.path[0]+"/dump/"
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

##EXPERIMENTAL!

def memoize(func):
    if os.path.exists(CACHE_FILE) and args.cache:
        debug("Using local cache ..")
        with open(CACHE_FILE) as f:
            cache = pickle.load(f)
    else:
        cache = {}
    @wraps(func)
    def wrap(*args):

        prj = args[1]
        cache_key = args[0]+prj.image_name

        if cache_key not in cache:
            print 'No cache, normal run'
            cache[cache_key] = func(*args)

            with open(CACHE_FILE, 'wb') as f:
                    pickle.dump(cache, f)

            if cache[cache_key]['status']:
                 # update the cache file
                with open(CACHE_FILE, 'wb') as f:
                    pickle.dump(cache, f)
            else:
                debug("Will not cache. Error found")
        else:
            debug("Loading results from cache")

        return cache[cache_key]
    return wrap

@memoize
def run_cmd(command, project):

    cmdp = cmd_processor.CommandProcessor()
    #print("\nSupported Commands:")
    #for cmd in cmdp.get_commands():
    #    print cmd
    debug("Running cmd: %s" %command)
    response = cmdp.prep_cmd(cmd_name=command, project=project)
    if not response['status']:
        err(response['message'])
    else:
        response = cmdp.get_result()
    if not response['status']:
        err("Command %s failed. Will not cache results" %command)
    return response


def main():

    if args.debug:
        set_debug(True)

    if not os.path.isfile(args.reportTemplate):
        print("ERROR: Report template not found: %s" % args.reportTemplate)
        return
    if not os.path.isfile(args.memoryImageFile):
        print("ERROR: Memory image file not found: %s" % args.memoryImageFile)
        return

    if args.hash:
        debug("Generating image hash")
        md5 = md5sum(args.memoryImageFile)
        debug("MD5:%s" %md5)
    else:
        md5 = "NONE"

    current_wd = sys.path[0]
    project = Project(current_wd)
    project.init_db(DB_NAME)
    project.set_image_name(args.memoryImageFile)

    if args.profile:
        project.set_volatility_profile(args.profile)
        debug("Using %s" % project.get_volatility_profile())
    else:
        print("No profile provided")

    if args.initdb:
        project.clean_db()

    debug("Loaded project settings")

    debug("Project root: [%s]" % project.get_root())
    debug("Plugins dir: [%s]" % project.plugins_dir)
    debug("Report export dir: [%s]" % project.report_export_location)
    debug("Pyplot flag: [%s]" % project.pyplot_flag)

    response = run_cmd("vol_imageinfo", project)

    if not response['status']:
        err(response['message'])
        #Fatal cannot continue
        exit()

    image_info = response['cmd_results']
    print_cmd_results(image_info)

    ##Set global target image values
    project.set_image_kdgb(image_info['KDBG'])
    image_info['image_name'] = project.get_image_name()
    profile_array = image_info['Suggested Profile(s)'].split(",")

    if project.get_volatility_profile() == "":
        for n in range(0, len(profile_array)):
            print("%s) %s" %(n, profile_array[n].strip()))
        print("If you see only profile names then select a number. If not use the full word")
        choice = raw_input("Please enter profile number or name: ")
        try:
            profile = profile_array[int(choice)].strip()
        except Exception, e:
            profile = choice

        project.set_volatility_profile(profile)
    else:
        profile = project.get_volatility_profile()

    if choice == "":
        err("No profile selected")
        exit()

    print("\nWill be using profile: %s" % project.get_volatility_profile())

    ##### Basic image info retrieved #####

    response = run_cmd("vol_getosversion", project)

    if not response['status']:
        err(response['message'])
        version_info = "{}"
    else:
        version_info = response['cmd_results']

    response = run_cmd("vol_pslist", project)
    if not response['status']:
        err(response['message'])
    rule_violations = response['cmd_results']['violations']
    plist = response['cmd_results']['plist']
    eplist = response['cmd_results']['plist_extended']
    suspicious_plist = response['cmd_results']['suspicious_processes']


    response = run_cmd("vol_malfind_extend", project)
    if not response['status']:
        err(response['message'])
    malprocesses = response['cmd_results']


    response = run_cmd("vol_regdump", project)
    if not response['status']:
        err(response['message'])
    user_info = response['cmd_results']

    response = run_cmd("vol_netscan", project)
    if not response['status']:
        err(response['message'])

    if 'network' not in response['cmd_results']:
        network_info = {}
    else:
        network_info = response['cmd_results']['network']


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
        malprocesses = malprocesses,
        plist=plist,
        eplist=eplist,
        suspicious_plist=suspicious_plist,
        users=user_info,
        network_info=network_info

    )
    debug("Writing report ..")
    fo.write(mytemplate.encode('utf-8'))
    fo.close

if __name__ == "__main__":
    main()

