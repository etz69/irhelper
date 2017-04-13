import subprocess
import sys
import json
import re
import collections
import ConfigParser

sys.path.append(sys.path[0]+"/../../")
from modules.db.ops import *

result = {'status': True, 'message': '', 'cmd_results': {}}
GLOBALS = {}



##TODO: Create a function to load variables from settings
# like DBNAME = "results.db"


def vol_pslist(image_file, globals_in):

    global GLOBALS,result
    GLOBALS = globals_in


    ######TEST AREA
    ######TEST AREA

    print_header("Executing vol_pslist...")
    cmd_array = []
    cmd_array.append("vol.py")
    if "_cache" in GLOBALS:
        cmd_array.append('--cache')
    cmd_array.append('--profile='+GLOBALS['_VOLATILITY_PROFILE'])
    if "_KDBG" in GLOBALS:
        cmd_array.append('--kdbg='+GLOBALS['_KDBG'])
    cmd_array.append('-f')
    cmd_array.append(image_file)
    #The command and the output
    cmd_array.append('pslist')
    cmd_array.append('--output=sqlite')
    cmd_array.append('--output-file=results.db')

    debug(cmd_array)

    _proc = subprocess.Popen(cmd_array, stdout=subprocess.PIPE)
    debug("Child process pid: %s" %_proc.pid)

    rc = _proc.poll()
    while rc == None:
        cmd_out =_proc.stdout.read()
        rc = _proc.poll()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "pslist command failed!"
        err(result['message'])

    print("Gathering more process info...")

    cmd_array = []
    cmd_array.append("vol.py")
    cmd_array.append('--plugins='+GLOBALS['PLUGIN_DIR'])

    if '_cache' in GLOBALS:
        cmd_array.append('--cache')
    if "_KDBG" in GLOBALS:
        cmd_array.append('--kdbg='+GLOBALS['_KDBG'])
    cmd_array.append('--profile='+GLOBALS['_VOLATILITY_PROFILE'])
    cmd_array.append('-f')
    cmd_array.append(image_file)
    #The command and the output
    cmd_array.append('psinfo2')

    debug(cmd_array)

    _proc = subprocess.Popen(cmd_array, stdout=subprocess.PIPE)
    debug("Child process pid: %s"%_proc.pid)

    rc = _proc.poll()
    while rc == None:
        cmd_out =_proc.stdout.read()
        rc = _proc.poll()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "psinfo2 command failed!"
        err(result['message'])

    if result['status']:
        processinfo_data = []

        for line in cmd_out.split("\n"):
            try:
                psinfo_line = line.rstrip("\n").split("|")
                psinfo = {}
                psinfo['process'] = psinfo_line[0]
                psinfo['process_fullname'] = psinfo_line[1]
                psinfo['pid'] = psinfo_line[2]
                psinfo['ppid'] = psinfo_line[3]
                psinfo['imagepath'] = psinfo_line[4]
                psinfo['cmdline'] = psinfo_line[5].replace(" ","/").split("//")[0].replace("\/\"","|").replace("\"","")

                processinfo_data.append(psinfo.copy())
            except Exception,e:
                err(e)
                debug(line)

        _table_name = "psinfo2"
        rdb = DBOps("results.db")
        rdb.new_table(_table_name, {'process':'text','process_fullname':'text',
                                  'pid':'integer', 'ppid':'text','imagepath':'text',
                                  'cmdline':'text'})

        rdb.insert_into_table(_table_name, processinfo_data)

    cmd = "vol.py verinfo --cache -f "+image_file+\
          " --profile="+GLOBALS['_VOLATILITY_PROFILE']+\
          " --output-file=results.db --output=sqlite"

    debug(cmd)
    _proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    _proc.wait()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "verinfo plugin failed!"
        err(result['message'])

    ###Dump pslist processes in dump dir and run checks

    cmd = "vol.py procdump --cache -f "+image_file+\
          " --profile="+GLOBALS['_VOLATILITY_PROFILE']+\
          " -D dump/"

    _proc = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE)
    debug("Child process pid: %s"%_proc.pid)

    rc = _proc.poll()
    while rc == None:
        cmd_out =_proc.stdout.read()
        rc = _proc.poll()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "procdump command failed!"
        err(result['message'])

    ##Run exiftool and store information

    #cmd = "exiftool -j pslist_dump/*"
    cmd_array = []
    cmd_array.append('exiftool')
    cmd_array.append('-j')
    cmd_array.append('-q')
    cmd_array.append(GLOBALS['DUMP_DIR'])

    debug(cmd_array)

    _proc = subprocess.Popen(cmd_array, stdout=subprocess.PIPE)
    debug("Child process pid: %s"%_proc.pid)

    rc = _proc.poll()
    while rc == None:
        cmd_out =_proc.stdout.read()
        rc = _proc.poll()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "exiftool command failed!"
        err(result['message'])

    if result['status']:
        debug("Loading exiftool results to DB")

        jdata = json.loads(cmd_out)
        jdata_keys = []

        for i in jdata:
            for n in i.keys():
                if n not in jdata_keys:
                    jdata_keys.append(n)

        table_columns = {}
        for x in jdata_keys:
            table_columns[x] = "text"

        _table_name = "exiftool"
        rdb = DBOps("results.db")
        rdb.new_table_from_keys(_table_name, table_columns)

        rdb.insert_into_table(_table_name, jdata)

        result['cmd_results'] = "PS info finished"

    ##Now run the analyser code
    violations = analyse_processes()
    result['cmd_results'] = violations



    #enrich_exif_with_shanon_entropy()



def enrich_exif_with_shanon_entropy():
    '''
    The information returned from the exiftool and psinfo contains a lot of
    information about the extracted files. To have a more complete view of
    the extracted files we can also add entropy information

    @param: the data dictionary from exiftool

    '''
    print_header("Calculating entropy of dumped files")

    rdb = DBOps("results.db")
    rdb.add_column_ifnot_exists('exiftool','sentropy','REAL')

    rows = rdb.get_all_rows('exiftool')
    for rs in rows:
        sn = str(calculate_shanon_entropy_file(rs['SourceFile']))

        table_name = "exiftool"
        column_name = "sentropy"
        value = sn
        key_name = "SourceFile"
        _key = rs['SourceFile']
        rdb.update_value(table_name, column_name, value, key_name, _key)



def analyse_processes():
    '''
    This module will check all running processes to verify that the correct
    parent process has spawned the running one.
    Some code has been taken from DAMM - Copyright (c) 2013 504ENSICS Labs

    @param: param

    '''
    print_header("Analysing processes")
    global GLOBALS
    debug(GLOBALS)

    violations = []
    violations_count = 0
    violation_message = {'process':'','rule': '','details':''}

    known_processes_XP = {
        'system'        : { 'pid' : 4, 'imagepath' : '', 'user_account' : 'Local System', 'parent' : 'none', 'singleton' : True, 'prio' : '8' },
        'smss.exe'      : {'imagepath' : 'windows\System32\smss.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'system', 'singleton' : True, 'session' : '', 'prio' : '11' },
        'lsass.exe'     : {'imagepath' : 'windows\system32\lsass.exe', 'user_account' : 'Local System', 'parent' : 'winlogon.exe', 'singleton' : True, 'session' : '0', 'prio' : '9', 'childless' : True, 'starts_at_boot' : True, 'starts_at_boot' : True },
        'winlogon.exe'  : {'imagepath' : 'windows\system32\winlogon.exe', 'user_account' : 'Local System', 'session' : '0', 'prio' : '13' },
        'csrss.exe'     : {'imagepath' : 'windows\system32\csrss.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'session' : '0', 'prio' : '13', 'starts_at_boot' : True },
        'services.exe'  : {'imagepath' : 'windows\system32\services.exe' , 'parent' : 'winlogon.exe', 'session' : '0', 'prio' : '9', 'starts_at_boot' : True },
        'svchost.exe'   : {'imagepath' : 'windows\System32\svchost.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'], 'parent' : 'services.exe', 'singleton' : False, 'session' : '0', 'prio' : '8', 'starts_at_boot' : True },
        'explorer.exe'  : {'imagepath' : 'windows\explorer.exe' , 'prio' : '8' },
    }

###Notes:
###wininit.exe starts from an instance of smss.exe that exits so most likely the parent does not exist

    known_processes_Vista = {
        'system'        : { 'pid' : 4, 'image_path' : '', 'user_account' : 'Local System', 'parent' : 'none', 'singleton' : True, 'prio' : '8' },
        'smss.exe'      : {'image_path' : 'windows\System32\smss.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'system', 'singleton' : True, 'session' : '', 'prio' : '11' },
        'wininit.exe'   : {'image_path' : 'windows\System32\wininit.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'none', 'session' : '0', 'children' : False, 'prio' : '13', 'starts_at_boot' : True },
        'lsass.exe'     : {'image_path' : 'windows\system32\lsass.exe' , 'user_account' : 'Local System', 'parent' : 'wininit.exe', 'singleton' : True, 'session' : '0', 'prio' : '9', 'childless' : True, 'starts_at_boot' : True },
        'winlogon.exe'  : {'image_path' : 'windows\system32\winlogon.exe' , 'user_account' : 'Local System', 'session' : '1' , 'prio' : '13'},
        'csrss.exe'     : {'image_path' : 'windows\system32\csrss.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'prio' : '13', 'starts_at_boot' : True },
        'services.exe'  : {'image_path' : 'windows\system32\services.exe' , 'parent' : 'wininit.exe', 'session' : '0', 'prio' : '9', 'starts_at_boot' : True },
        'svchost.exe'   : {'image_path' : 'windows\System32\svchost.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'], 'parent' : 'services.exe', 'singleton' : False, 'session' : '0', 'prio' : '8', 'starts_at_boot' : True },
        'lsm.exe'      : {'image_path' : 'windows\System32\lsm.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'wininit.exe', 'session' : '0', 'prio' : '8', 'childless' : True, 'starts_at_boot' : True },
        'explorer.exe'  : {'image_path' : 'windows\explorer.exe' , 'prio' : '8' },
    }

    ##First we need to construct relevant process information structure so
    #we can easily verify them

    ##for every process in our running list
    ##{pid:2,ppid:3,path:xxx}
    ## check by name
    ## example:
    ## get the element with name system from our list and check if each key matches the required value

    #process_fullname|process    |pid|ppid|imagepath                    |Hnds|Sess|Thds
    #NoPEB           |System     |4  |0   |NoPEB                        |1003|-1  |65

    ##First put all processes from pslist with enriched info into an array
    con = sqlite3.connect('results.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute('select psinfo2.process_fullname,psinfo2.process,psinfo2.pid,psinfo2.ppid,'
                'psinfo2.imagepath,pslist.hnds,pslist.sess,pslist.thds, '
                '(SELECT ps2.process_fullname FROM psinfo2 ps2 WHERE ps2.pid = psinfo2.ppid) AS parentname'
                ' from psinfo2 inner join pslist on psinfo2.pid = pslist.pid')

    rows = cur.fetchall()
    target_process_list = []
    full_pslist_dict = {}

    for rs in rows:

        ps = {}
        ps['pid'] = rs['pid']
        ps['imagepath'] = str(rs['imagepath']).lower().lstrip("c:/\/")
        ps['imagepath'] = str(ps['imagepath']).lstrip('??/\/\c:/\/\/')
        ps['imagepath'] = str(ps['imagepath']).replace('systemroot','windows')
        if ps['imagepath'] == "nopeb":
            ps['imagepath'] = ''



        ps['ppid'] = rs['ppid']
        ps['parent'] = str(rs['parentname']).lower()
        if rs['ppid'] == "4":
            ps['parent'] = "system"
        ps['name'] = rs['process'].lower()
        if rs['process'].lower() == "system":
            ps['fullname'] = str(rs['process']).lower()
        else:
            ps['fullname'] = rs['process_fullname'].lower()


        target_process_list.append(ps.copy())
        full_pslist_dict[ps['name']] = ps.copy()

    if str(GLOBALS['_VOLATILITY_PROFILE']).startswith("WinXP") or str(GLOBALS['_VOLATILITY_PROFILE']).startswith("Win2003"):
        rule_list = known_processes_XP
    else:
        rule_list = known_processes_Vista

    for key in rule_list:
        for process in target_process_list:
            if re.search(process['name'],key, re.IGNORECASE):
                for check in rule_list[key]:
                    if check in process:
                        if not str(process[check]).lower() == str(rule_list[key][check]).lower():

                            print("Violation detected on: [%s] Actual value: [%s] Expected value: [%s]" %(check,process[check],rule_list[key][check]))
                            print(process)
                            violations_count += 1
                            violation_message['id'] = violations_count
                            violation_message['process'] = process
                            violation_message['rule'] = check
                            violation_message['details'] = ("Violation detected on: [%s] Actual value: [%s] Expected value: [%s]" %(check,process[check],rule_list[key][check]))
                            violations.append(violation_message.copy())


    ##Check for singleton violations as DAMM call it
    processes = []
    for process in target_process_list:
        processes.append(str(process['name']).lower())

    counter=collections.Counter(processes)

    for key in rule_list:

        if key in processes and "singleton" in rule_list[key]:
            if int(counter[key]) > 1 and rule_list[key]['singleton']:
                print("Violation detected on: [singleton] condition from [%s] Actual value: [%s]" %(key,int(counter[key])))
                violations_count += 1
                violation_message['id'] = violations_count
                violation_message['process'] = full_pslist_dict[key]
                violation_message['rule'] = "[Singleton]"
                violation_message['details'] = ("Violation detected on: [singleton] condition from [%s] Actual value: [%s]" %(key,int(counter[key])))
                violations.append(violation_message.copy())
                print(full_pslist_dict[key])

    ####Lets try to detect similar wording in well known processes
    usual_suspects = ['smss.exe', 'wininit.exe','csrss.exe','svchost.exe',
                      'lsass.exe','lsm.exe','wmpnetwk.exe','wuauclt.exe']

    ##Injecting bad process names
    #target_process_list.append("scvhost.exe")
    #target_process_list.append("lsa.exe")

    for process in target_process_list:
        for suspect in usual_suspects:
            flag, score = score_jaro_distance(process,suspect)
            if flag:
                print("Possible culrpit process detected: [%s] resembles to: [%s] Score: [%s]" %(process,suspect,score))
                violations_count += 1
                violation_message['id'] = violations_count
                violation_message['process'] = process
                violation_message['rule'] = "[Culrpit]"
                violation_message['details'] = ("Possible culrpit process detected: [%s] resembles to: [%s] Score: [%s]" %(process,suspect,score))
                violations.append(violation_message.copy())

    return violations

def get_result():
    return result

def show_json(in_response):
    ##Function to test json output
    print(json.dumps(in_response, sort_keys=False, indent=4))


if __name__ == "__main__":
    print("Python version: %s\n " %sys.version)

    ##When entering via main the paths change
    GLOBALS = {}
    set_debug(True)

    ##Load settings.py
    settings = sys.path[0]+"/../../settings.py"
    config = ConfigParser.ConfigParser()

    config.read(settings)
    GLOBALS['PLUGIN_DIR'] = config.get('Directories', 'plugins').strip("'")
    GLOBALS['DUMP_DIR'] = config.get('Directories', 'dump').strip("'")

    ##Get module parameters
    action = sys.argv[1]
    image = sys.argv[2]
    profile = sys.argv[3]

    ##Load required GLOBALS
    GLOBALS['_VOLATILITY_PROFILE'] = profile
    GLOBALS['_cache'] = True
    for key in GLOBALS:
        debug("%s: %s" %(key, GLOBALS[key]))

    ##Call the actual command
    vol_pslist(image, GLOBALS)
    show_json(get_result())

    d = get_result()
    print
    print d['cmd_results']['violations'][0]