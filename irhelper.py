import pickle
import argparse
from jinja2 import Environment, FileSystemLoader


from modules import cmd_processor
from modules.utils.helper import *
import sys
import os
from datetime import datetime
import pytz

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

parser.add_argument("-p", '--profile', nargs='?', help="Volatility profile (Optional)")
parser.add_argument("-r", '--risk', nargs='?', help="Risk level to show processes (default 2)")
parser.add_argument('--cache', action="store_true", help="Enable cache")
parser.add_argument('--debug', action="store_true", help="Run in debug")
parser.add_argument('--initdb', action="store_true", help="Initialise local DB")
parser.add_argument('--hash', action="store_true", help="Generate hashes")
parser.add_argument('--vt', action="store_true", help="Check VirusTotal for suspicious hash (API KEY required)")
parser.add_argument('--osint', action="store_true", help="Check C1fApp for OSINT of ip/domain (API KEY required)")
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

    debug("Running cmd: %s" % command)
    response = cmdp.prep_cmd(cmd_name=command, project=project)
    if not response['status']:
        err(response['message'])
    else:
        response = cmdp.get_result()
    if not response['status']:
        err("Command %s failed. Will not cache results" %command)
    return response


def main():
    if os.geteuid() == 0:
        exit("You must not run this code with root privileges")

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
        debug("MD5:%s" % md5)
        sha1 = sha1sum(args.memoryImageFile)
        debug("SHA1:%s" % sha1)
    else:
        md5 = "NONE"
        sha1 = "NONE"

    utc = pytz.UTC
    analysis_timestamp = utc.localize(datetime.now())
    analysis_timestamp = analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')

    if args.vt:
        vt_check = True
    else:
        vt_check = False

    r = range(1, 4)
    if args.risk:
        if not isinstance(args.risk, int) and int(args.risk) not in r:
            err("Risk level should be integer from 1-4")
            sys.exit(1)
        risk_level = args.risk
    else:
        risk_level = None

    current_wd = sys.path[0]
    project = Project(current_wd)
    project.init_db(DB_NAME)
    project.set_image_name(args.memoryImageFile)
    risk_index = list()

    if args.profile:
        project.set_volatility_profile(args.profile)
        debug("Using %s" % project.get_volatility_profile())

    if args.initdb:
        project.clean_db()

    debug("Loaded project settings")

    debug("Project root: [%s]" % project.get_root())
    debug("Plugins dir: [%s]" % project.plugins_dir)
    debug("Report export dir: [%s]" % project.report_export_location)
    debug("Pyplot flag: [%s]" % project.pyplot_flag)

    ####FINISHED INITIALIZATION

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
    rprofile_array = image_info['Suggested Profile(s)'].split(",")
    profile_array = []
    for profile in rprofile_array:
        profile_array.append(profile.strip().split(" ")[0])

    if project.get_volatility_profile() == "":
        for n in range(0, len(profile_array)):
            print("%s) %s" %(n, profile_array[n].strip()))
        print("If you see only profile names then select a number. If not use the full word")
        choice = raw_input("Please enter profile number or name: ")
        try:
            profile = profile_array[int(choice)].strip()
        except Exception as e:
            profile = choice

        project.set_volatility_profile(profile)
    else:
        profile = project.get_volatility_profile()

    if choice == "":
        err("No profile selected")
        exit()

    print("\nWill be using profile: %s" % project.get_volatility_profile())

    ##### Basic image info retrieved #####
    errors = list()

    response = run_cmd("vol_getosversion", project)

    if not response['status']:
        err(response['message'])
        version_info = "{}"
    else:
        version_info = response['cmd_results']

    response = run_cmd("vol_pslist", project)
    if not response['status']:
        err(response['message'])
    errors.append(response['errors'])
    rule_violations = response['cmd_results']['violations']
    plist = response['cmd_results']['plist']
    eplist = response['cmd_results']['plist_extended']
    suspicious_plist = response['cmd_results']['suspicious_processes']
    risk_index.append(response['risk_index'])

    response = run_cmd("vol_malfind_extend", project)
    if not response['status']:
        err(response['message'])
    errors.append(response['errors'])
    malprocesses = response['malfind']
    hollowprocesses = response['hollow']

    risk_index.append(response['risk_index'])

    response = run_cmd("vol_regdump", project)
    errors.append(response['errors'])
    if not response['status']:
        err(response['message'])
    user_info = response['cmd_results']

    response = run_cmd("vol_netscan", project)
    errors.append(response['errors'])
    if not response['status']:
        err(response['message'])

    if 'network' not in response['cmd_results']:
        network_info = {}
    else:
        network_info = response['cmd_results']['network']
    debug(network_info)

    #network_info = get_cifapp_info(network_info)
    #debug(network_info)

    response = run_cmd("vol_cmdscan", project)
    errors.append(response['errors'])
    if not response['status']:
        err(response['message'])
    cmd_info = response['cmd_results']['cmds']

    risk_index_final = calculate_risk(risk_index, eplist,plist, risk_level)


    ### CHECK IF VT IS REQUESTED
    if vt_check:
        risk_index_final = check_hash_vt(risk_index_final, check=True)
    else:
        risk_index_final = check_hash_vt(risk_index_final, check=False)
    ##Write to template
    if not os.path.exists("export"):
        os.makedirs("export")

    exportpath = "export/{}".format(args.reportTemplate.split("/")[1])
    fo = open(exportpath, "w")

    env = Environment(loader=FileSystemLoader("./"), trim_blocks=True)
    print("Violations: %s" % len(rule_violations))

    mytemplate = env.get_template(args.reportTemplate).render(
        profiles=",".join(profile_array),
        working_profile=project.get_volatility_profile(),
        image_info=image_info,
        analysis_timestamp=analysis_timestamp,
        image_md5=md5,
        image_sha1=sha1,
        errors=errors,
        version_info=version_info,
        rule_violations=rule_violations,
        malprocesses=malprocesses,
        hollowprocesses=hollowprocesses,
        plist=plist,
        eplist=eplist,
        suspicious_plist=suspicious_plist,
        users=user_info,
        cmd_info=cmd_info,
        network_info=network_info,
        risk_index=risk_index_final

    )
    debug("Writing report to [%s]" % exportpath)
    fo.write(mytemplate.encode('utf-8'))
    fo.close

if __name__ == "__main__":
    main()