import re
import collections
import json
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *
from modules.db import DBops as dbops

##TODO remove sqlite and create dbops
import sqlite3

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}


def vol_pslist(project):
    global result

    ######TEST AREA

    ######TEST AREA


    print_header("Executing vol_pslist...")
    rdb = dbops.DBOps(project.db_name)

    if not rdb.table_exists("PSList"):
        rc, result = execute_volatility_plugin(plugin_type="default",
                                                plugin_name="pslist",
                                                output="db",
                                                result=result,
                                                project=project,
                                                shell=False,
                                                dump=False,
                                                plugin_parms=None)

        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])

    print("Gathering more process info...")

    if not rdb.table_exists("psinfo2"):
        rc, result = execute_volatility_plugin(plugin_type="contrib",
                                                plugin_name="psinfo2",
                                                output="stdout",
                                                result=result,
                                                project=project,
                                                shell=False,
                                                dump=False,
                                                plugin_parms=None)

        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])

    if result['status']:

        processinfo_data = []

        for line in result['cmd_results'].split("\n"):
            try:
                psinfo_line = line.rstrip("\n").split("|")
                psinfo = {}
                psinfo['process'] = psinfo_line[0]
                psinfo['process_fullname'] = psinfo_line[1]
                psinfo['pid'] = psinfo_line[2]
                psinfo['ppid'] = psinfo_line[3]
                psinfo['imagepath'] = psinfo_line[4]
                psinfo['cmdline'] = psinfo_line[5].replace(" ","/").split("//")[0].replace("\/\"","|").replace("\"","")

                if psinfo_line[2] == "4":
                    psinfo['process_fullname'] = "system"

                processinfo_data.append(psinfo.copy())
            except Exception, e:
                err(e)
                debug(line)

        _table_name = "psinfo2"

        rdb = dbops.DBOps(project.db_name)
        rdb.new_table(_table_name, {'process':'text','process_fullname':'text',
                                  'pid':'integer', 'ppid':'text','imagepath':'text',
                                  'cmdline':'text'})

        rdb.insert_into_table(_table_name, processinfo_data)

    if not rdb.table_exists("VerInfo"):
        rc, result = execute_volatility_plugin(plugin_type="default",
                                                plugin_name="verinfo",
                                                output="db",
                                                result=result,
                                                project=project,
                                                shell=False,
                                                dump=False,
                                                plugin_parms=None)
        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])


    ###Dump pslist processes in dump dir and run checks
    rc, result = execute_volatility_plugin(plugin_type="default",
                                             plugin_name="procdump",
                                             output="stdout",
                                             result=result,
                                             project=project,
                                             shell=True,
                                             dump=True,
                                             plugin_parms=None)

    ##Run exiftool and store information
    if not rdb.table_exists("exiftool"):

        #cmd = "exiftool -j pslist_dump/*"
        cmd_array = []
        cmd_array.append('exiftool')
        cmd_array.append('-j')
        cmd_array.append('-q')
        cmd_array.append(project.dump_dir)

        debug(cmd_array)
        try:
            rc = subprocess.check_output(cmd_array)
            result['status'] = True
            cmd_out = rc
        except subprocess.CalledProcessError as e:
            result['status'] = False
            result['message'] = "Exception: exiftool plugin failed!"
            err(result['message'])

        if result['status']:
            debug("Loading exiftool results to DB")

            try:

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
                rdb = dbops.DBOps(project.db_name)
                rdb.new_table_from_keys(_table_name, table_columns)

                rdb.insert_into_table(_table_name, jdata)
                result['cmd_results'] = "PS info finished"
            except Exception as e:
                err("Error running exiftool")
                result['errors'].append(e)

    ##Now run the analyser code
    violations, plist = analyse_processes(project)
    result['cmd_results'] = {'violations': [], 'plist': [],
                             'plist_extended': [],
                             'suspicious_processes': [],}

    result['cmd_results']['plist'] = plist
    result['cmd_results']['violations'] = violations

    enrich_exif_with_shanon_entropy()
    calculate_md5()

    epslist_data = enrich_pslist(project, plist)
    result['cmd_results']['plist_extended'] = epslist_data


    risk_list = analyse_scan_processes(project)
    suspicious_plist = []
    for p in risk_list:
        suspicious_process = {}
        suspicious_process['pid'] = p
        suspicious_process['risk'] = risk_list[p]
        for i in plist:
            if str(i['pid']) ==  str(p):
                suspicious_process['name'] = i['name']
                break
        suspicious_plist.append(suspicious_process.copy())
    result['cmd_results']['suspicious_processes'] = suspicious_plist


def enrich_pslist(project, plist):

    rdb = dbops.DBOps(project.db_name)
    query = "select FileName,CompanyName,OriginalFileName," \
            "FileDescription,FileSize,LegalCopyright,FileDescription,md5," \
            "InternalName,sentropy from exiftool"

    jdata = rdb.sqlite_query_to_json(query)

    for entry in jdata:
        new_entry = {}
        pid = entry['FileName'].split(".")[1]
        entry['pid'] = pid
        for e in plist:
            if str(pid) == str(e['pid']):
                entry['process_name'] = e['name']
        entry['sn_level'] = check_entropy_level(entry['sentropy'])

    return jdata


def calculate_md5():
    print_header("Calculating MD5 of dumped files. This may take a while")

    rdb = dbops.DBOps("results.db")
    rdb.patch_table('exiftool','md5','text')

    rows = rdb.get_all_rows('exiftool')
    for rs in rows:
        try:
            md5 = md5sum(rs['SourceFile'])
            table_name = "exiftool"
            column_name = "md5"
            value = str(md5)
            key_name = "SourceFile"
            _key = rs[key_name]
            rdb.update_value(table_name, column_name, value, key_name, _key)

        except Exception as e:
            err(e)


def enrich_exif_with_shanon_entropy():
    '''
    The information returned from the exiftool and psinfo contains a lot of
    information about the extracted files. To have a more complete view of
    the extracted files we can also add entropy information

    @param: the data dictionary from exiftool

    '''
    print_header("Calculating entropy of dumped files. This may take a while")
    get_a_cofee()

    rdb = dbops.DBOps("results.db")
    rdb.patch_table('exiftool','sentropy','REAL')

    rows = rdb.get_all_rows('exiftool')
    for rs in rows:
        try:
            sn = str(calculate_shanon_entropy_file(rs['SourceFile']))
            table_name = "exiftool"
            column_name = "sentropy"
            value = sn
            key_name = "SourceFile"
            _key = rs[key_name]
            rdb.update_value(table_name, column_name, value, key_name, _key)

        except Exception as e:
            pass




def analyse_processes(project):
    '''
    This module will check all running processes to verify that the correct
    parent process has spawned the running one.
    Some ideas like the rules format has been taken from DAMM - @ 504ENSICS Labs

    @param: param

    '''
    print_header("Analysing processes")


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

    ##TODO: here we need a more novel approach for the violation checks
    ## to minimise false positives . Not all information is available sometimes

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

    if str(project.get_volatility_profile()).startswith("WinXP") \
            or str(project.get_volatility_profile()).startswith("Win2003"):
        rule_list = known_processes_XP
    else:
        rule_list = known_processes_Vista

    for key in rule_list:
        for process in target_process_list:
            if re.search(process['name'], key, re.IGNORECASE):
                for check in rule_list[key]:
                    if check in process:
                        ###NOt all have peb information
                        if not str(process[check]).lower() == str(rule_list[key][check]).lower() and str(process[check]).lower() != "nopeb" :

                            print("Violation detected on: [%s] Actual value: [%s] Expected value: [%s]" %(check, process[check], rule_list[key][check]))
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

    return violations, target_process_list


def analyse_scan_processes(_project):

    ## First we retrieve psxview all processes
    global result
    print_header("Gathering information from scan process")

    rdb = dbops.DBOps(_project.db_name)
    if not rdb.table_exists("PsXview"):
        rc, result = execute_volatility_plugin(plugin_type="contrib",
                                                plugin_name="psxview",
                                                output="db",
                                                result=result,
                                                project=_project,
                                                shell=False,
                                                dump=False,
                                                plugin_parms=None)

        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])

    if not rdb.table_exists("ApiHooks"):
        rc, result = execute_volatility_plugin(plugin_type="contrib",
                                                plugin_name="apihooks",
                                                output="db",
                                                result=result,
                                                project=_project,
                                                shell=False,
                                                dump=False,
                                                plugin_parms=None)

        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])

    if not rdb.table_exists("Malfind"):
        rc, result = execute_volatility_plugin(plugin_type="contrib",
                                                plugin_name="malfind",
                                                output="db",
                                                result=result,
                                                project=_project,
                                                shell=False,
                                                dump=False,
                                                plugin_parms=None)

        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])


    ##Three arrays
    psxview = []
    apihooked = []
    malfinded = []
    process_risk = {}

    ## Analyse further the ones with PID=false psscan=True and ExitTime null
    #select * from psxview where pslist="False" and psscan="True" and exittime="";
    if rdb.table_exists("PsXview"):
        jdata = {}
        #query = 'select * from psxview where pslist=\"False\"' \
        #        ' and psscan=\"True\" and not ExitTime '
        query = "select * from psxview where psscan=\"True\""

        jdata = rdb.sqlite_query_to_json(query)
        for entry in jdata:

            psxview.append(entry['PID'])
            process_risk[entry['PID']] = 1
    else:
        err("No PSXView data")


    if rdb.table_exists("ApiHooks"):
        jdata = {}
        query = "select PID, Process, VictimModule, Function from ApiHooks"
        jdata = rdb.sqlite_query_to_json(query)
        for entry in jdata:
            apihooked.append(entry['PID'])
            if entry['PID'] in psxview:
                process_risk[entry['PID']] = 2
            else:
                process_risk[entry['PID']] = 1

    else:
        err("No ApiHooks data")


    if rdb.table_exists("Malfind"):
        jdata = {}
        query = "select Pid, Process from Malfind group by Pid"
        jdata = rdb.sqlite_query_to_json(query)
        for entry in jdata:
            malfinded.append(entry['Pid'])
            if entry['Pid'] in apihooked and entry['Pid'] in psxview:
                process_risk[entry['Pid']] = 3
            if entry['Pid'] in apihooked and entry['Pid'] not in psxview:
                process_risk[entry['Pid']] = 2
            if entry['Pid'] not in apihooked and entry['Pid'] in psxview:
                process_risk[entry['Pid']] = 2

    else:
        err("No Malfind data")


    ##Then for every process from above check the following :
    #1. apihooks
    #2. malfind
    # more to come this is just a very simple approach (there will be false positives as well
    ##Finally we assign a risk score:
    # 10 to the ones from psscan
    # 10 to the ones from apihooks
    # 10 to the ones in malfind (next version we identify shellcode with ML ! :)

    debug("Process risk list:%s " %process_risk)
    return process_risk

def get_result():
    return result

def show_json(in_response):
    ##Function to test json output
    print(json.dumps(in_response, sort_keys=False, indent=4))

if __name__ == "__main__":
    #
    print("Python version: %s\n " %sys.version)
    DB_NAME = "results.db"

    set_debug(True)

    ##Get module parameters
    image = sys.argv[1]
    profile = sys.argv[2]

    ##Call the actual command
    current_wd = sys.path[0]
    project = Project(current_wd)
    project.init_db(DB_NAME)
    project.set_volatility_profile(profile)
    project.set_image_name(image)

    vol_pslist(project)
    show_json(get_result())
