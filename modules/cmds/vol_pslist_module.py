import collections
import json
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *
from modules.db import DBops as dbops

##TODO remove sqlite and create dbops
import sqlite3

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}


def vol_pslist(_project):
    global result

    ######TEST AREA
    ######TEST AREA

    print_header("Executing vol_pslist...")
    rdb = dbops.DBOps(_project.db_name)

    vp_list = {'name': 'pslist', 'table': 'PSList',
               'output': 'db', 'type': 'default',
               'shell': False, 'dump': False, 'parms': None}

    ##Note this is stdout so we need to store for later
    vp_psinfo_out = ""
    vp_psinfo = {'name': 'psinfo2', 'table': 'psinfo2',
                 'output': 'stdout', 'type': 'contrib',
                 'shell': False, 'dump': False, 'parms': None}

    vp_verinfo = {'name': 'verinfo', 'table': 'VerInfo',
                  'output': 'db', 'type': 'default',
                  'shell': False, 'dump': False, 'parms': None}

    vp_dumpprocesses = {'name': 'procdump', 'table': 'ProcDump',
                        'output': 'db', 'type': 'default',
                        'shell': True, 'dump': True, 'parms': None}

    volatility_plugins = [vp_list, vp_psinfo, vp_verinfo, vp_dumpprocesses]

    for plugin in volatility_plugins:

        if not rdb.table_exists(plugin['table']):
            rc, result = execute_volatility_plugin(plugin_type=plugin['type'],
                                                   plugin_name=plugin['name'],
                                                   output=plugin['output'],
                                                   result=result,
                                                   project=_project,
                                                   shell=plugin['shell'],
                                                   dump=plugin['dump'],
                                                   plugin_parms=plugin['parms'])

            if result['status']:
                debug("CMD completed %s" % plugin['name'])
                if plugin['name'] == "psinfo2":
                    vp_psinfo_out = result['cmd_results']
            else:
                err(result['message'])

    if result['status']:

        processinfo_data = []

        for line in vp_psinfo_out.split("\n"):
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

        rdb = dbops.DBOps(_project.db_name)
        rdb.new_table(_table_name, {'process': 'text', 'process_fullname': 'text',
                                    'pid': 'integer', 'ppid': 'text',
                                    'imagepath': 'text',
                                    'cmdline': 'text'})

        rdb.insert_into_table(_table_name, processinfo_data)

    ##Run exiftool and store information
    if not rdb.table_exists("exiftool"):

        #cmd = "exiftool -j pslist_dump/*"
        cmd_array = []
        cmd_array.append('exiftool')
        cmd_array.append('-j')
        cmd_array.append('-q')
        cmd_array.append(_project.dump_dir)

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
                rdb = dbops.DBOps(_project.db_name)
                rdb.new_table_from_keys(_table_name, table_columns)

                rdb.insert_into_table(_table_name, jdata)
                result['cmd_results'] = "PS info finished"
            except Exception as e:
                err("Error running exiftool")
                result['errors'].append(e)

    ##Now run the analyser code part
    violations, plist = analyse_processes(_project)
    result['cmd_results'] = {'violations': [], 'plist': [],
                             'plist_extended': [],
                             'suspicious_processes': [],}

    result['cmd_results']['plist'] = plist
    result['cmd_results']['violations'] = violations

    enrich_exif_with_shanon_entropy()
    calculate_md5()

    epslist_data = enrich_pslist(_project, plist)
    result['cmd_results']['plist_extended'] = epslist_data

    risk_list = analyse_scan_processes(_project)
    suspicious_plist = []
    for p in risk_list:
        suspicious_process = dict()
        suspicious_process['pid'] = p
        suspicious_process['risk'] = risk_list[p]
        for i in plist:
            if str(i['pid']) == str(p):

                suspicious_process['name'] = i['name']
                break
        suspicious_plist.append(suspicious_process.copy())
    result['cmd_results']['suspicious_processes'] = suspicious_plist


def enrich_pslist(_project, plist):

    rdb = dbops.DBOps(_project.db_name)
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
    print_header("Calculating MD5 of dumped files..")

    rdb = dbops.DBOps("results.db")

    rdb.patch_table('exiftool','md5','text')

    if rdb.table_exists('exiftool'):
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
    try:
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
    except Exception as e:
        err("Error calculating entropy")

def analyse_processes(_project):
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
##svchost is accessing the network to public addresses (eg. Windows updateS) with ppid/name services.exe
    known_processes_Vista = {
        'system'        : { 'pid' : 4, 'image_path' : '', 'user_account' : 'Local System', 'parent' : 'none', 'singleton' : True, 'prio' : '8' ,'Public Net access': True, 'Private Net access': True},
        'smss.exe'      : {'image_path' : 'windows\System32\smss.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'system', 'singleton' : True, 'session' : '', 'prio' : '11' },
        'wininit.exe'   : {'image_path' : 'windows\System32\wininit.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'none', 'session' : '0', 'children' : False, 'prio' : '13', 'starts_at_boot' : True },
        'lsass.exe'     : {'image_path' : 'windows\system32\lsass.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'wininit.exe', 'singleton' : True, 'session' : '0', 'prio' : '9', 'childless' : True, 'starts_at_boot' : True },
        'winlogon.exe'  : {'image_path' : 'windows\system32\winlogon.exe' , 'user_account' : 'Local System', 'session' : '1' , 'prio' : '13'},
        'csrss.exe'     : {'image_path' : 'windows\system32\csrss.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'prio' : '13', 'session' : '1', 'starts_at_boot' : True },
        'services.exe'  : {'image_path' : 'windows\system32\services.exe' , 'parent' : 'wininit.exe', 'session' : '0', 'prio' : '9', 'starts_at_boot' : True },
        'svchost.exe'   : {'image_path' : 'windows\System32\svchost.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'], 'parent' : 'services.exe', 'singleton' : False, 'session' : '0', 'prio' : '8', 'starts_at_boot' : True ,'Public Net access': True, 'Private Net access': True},
        'lsm.exe'       : {'image_path' : 'windows\System32\lsm.exe' , 'user_account' : ['NT AUTHORITY\SYSTEM'], 'parent' : 'wininit.exe', 'session' : '0', 'prio' : '8', 'childless' : True, 'starts_at_boot' : True },
        'explorer.exe'  : {'image_path' : 'windows\explorer.exe' , 'parent' : 'none','session' : '1' ,'singleton' : False, 'prio' : '8' },
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
    target_process_list = []
    rows = []
    full_pslist_dict = dict()

    con = sqlite3.connect(_project.db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    rdb = dbops.DBOps(_project.db_name)
    if rdb.table_exists("psinfo2") and rdb.table_exists("PSList"):
        cur.execute('select psinfo2.process_fullname,psinfo2.process,psinfo2.pid,'
                    'psinfo2.ppid,'
                    'psinfo2.imagepath,pslist.hnds,pslist.sess,pslist.thds, '
                    '(SELECT ps2.process_fullname FROM psinfo2 ps2 '
                    'WHERE ps2.pid = psinfo2.ppid) AS parentname'
                    ' from psinfo2 inner join pslist on psinfo2.pid = pslist.pid')

        rows = cur.fetchall()

    for rs in rows:
        ps = dict()
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

    if str(_project.get_volatility_profile()).startswith("WinXP") \
            or str(_project.get_volatility_profile()).startswith("Win2003"):
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

                            print("Violation detected on: [%s] "
                                  "Actual value: [%s] Expected value: [%s]"
                                  % (check, process[check], rule_list[key][check]))
                            print(process)
                            violations_count += 1
                            violation_message['id'] = violations_count
                            violation_message['process'] = process
                            violation_message['rule'] = check
                            violation_message['details'] = ("Violation detected on: [%s] "
                                                            "Actual value: [%s] Expected value: [%s]"
                                                            % (check, process[check], rule_list[key][check]))
                            violations.append(violation_message.copy())


    ##Check for singleton violations as DAMM call it
    processes = []
    for process in target_process_list:
        processes.append(str(process['name']).lower())

    counter = collections.Counter(processes)

    for key in rule_list:

        if key in processes and "singleton" in rule_list[key]:
            if int(counter[key]) > 1 and rule_list[key]['singleton']:
                print("Violation detected on: [singleton] condition "
                      "from [%s] Actual value: [%s]" % (key, int(counter[key])))
                violations_count += 1
                violation_message['id'] = violations_count
                violation_message['process'] = full_pslist_dict[key]
                violation_message['rule'] = "[Singleton]"
                violation_message['details'] = ("Violation detected on: "
                                                "[singleton] condition "
                                                "from [%s] Actual value: [%s]"
                                                % (key, int(counter[key])))
                violations.append(violation_message.copy())
                print(full_pslist_dict[key])

    ####Lets try to detect similar wording in well known processes
    usual_suspects = ['smss.exe', 'wininit.exe', 'csrss.exe', 'svchost.exe',
                      'lsass.exe', 'lsm.exe', 'wmpnetwk.exe', 'wuauclt.exe']

    ##Injecting bad process names
    #target_process_list.append("scvhost.exe")

    for process in target_process_list:
        for suspect in usual_suspects:
            flag, score = score_jaro_distance(process,suspect)
            if flag:
                print("Possible culrpit process detected: [%s] "
                      "resembles to: [%s] Score: [%s]"
                      % (process, suspect, score))
                violations_count += 1
                violation_message['id'] = violations_count
                violation_message['process'] = process
                violation_message['rule'] = "[Culrpit]"
                violation_message['details'] = ("Possible culrpit process "
                                                "detected: [%s] resembles "
                                                "to: [%s] Score: [%s]"
                                                % (process, suspect, score))
                violations.append(violation_message.copy())

    return violations, target_process_list


def analyse_scan_processes(_project):

    ## First we retrieve psxview all processes
    global result
    print_header("Gathering information from scan process")

    rdb = dbops.DBOps(_project.db_name)

    vp_psxview = {'name': 'psxview', 'table': 'PsXview',
                  'output': 'db', 'type': 'default',
                  'shell': False, 'dump': False, 'parms': None}

    vp_apihooks = {'name': 'apihooks', 'table': 'ApiHooks',
                   'output': 'db', 'type': 'default',
                   'shell': False, 'dump': False, 'parms': '-Q'}

    vp_malfind = {'name': 'malfind', 'table': 'Malfind',
                  'output': 'db', 'type': 'default',
                  'shell': False, 'dump': False, 'parms': None}

    volatility_plugins = [vp_psxview, vp_apihooks, vp_malfind]

    for plugin in volatility_plugins:

        if not rdb.table_exists(plugin['table']):
            rc, result = execute_volatility_plugin(plugin_type=plugin['type'],
                                                   plugin_name=plugin['name'],
                                                   output=plugin['output'],
                                                   result=result,
                                                   project=_project,
                                                   shell=plugin['shell'],
                                                   dump=plugin['dump'],
                                                   plugin_parms=plugin['parms'])

            if result['status']:
                debug("CMD completed %s" % plugin['name'])
            else:
                err(result['message'])

    psxview = []
    apihooked = []
    malfinded = []
    process_risk = dict()

    ## Analyse further the ones with PID=false psscan=True and ExitTime null
    #select * from psxview where pslist="False" and psscan="True" and exittime="";
    if rdb.table_exists("PsXview"):
        query = "SELECT * FROM psxview WHERE psscan=\"True\""

        jdata = rdb.sqlite_query_to_json(query)
        for entry in jdata:

            psxview.append(entry['PID'])
            process_risk[entry['PID']] = 1
    else:
        err("No PSXView data")

    if rdb.table_exists("ApiHooks"):
        query = "SELECT PID, Process, VictimModule, Function FROM ApiHooks"
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
        query = "SELECT Pid, Process FROM Malfind GROUP BY Pid"
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
    # more to come this is just a very simple approach (there will
    # be false positives as well
    ##Finally we assign a silly risk score:
    # 10 to the ones from psscan
    # 10 to the ones from apihooks
    # 10 to the ones in malfind (next version we identify shellcode with ML! :)
    debug("Process risk list:%s " % process_risk)
    return process_risk


def get_result():
    return result


def show_json(in_response):
    ##Function to test json output
    try:
        print(json.dumps(in_response, sort_keys=False, indent=4))
    except TypeError as e:
        print(json.dumps({"error": "Error with decoding JSON"},
                         sort_keys=False, indent=4))


if __name__ == "__main__":
    #
    print("Python version: %s\n " % sys.version)
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
