# Author: Adapted by Monnappa K A
# Email : info@evoxco.com
# Twitter: @etz69
# Description: Volatility Plugin to display process related information.
# Cutdown version of psinfo

import os
import volatility.obj as obj
from volatility.plugins.taskmods import PSList
import volatility.plugins.vadinfo as vadinfo
from volatility.renderers.basic import Address,Hex


class PsInfo2(vadinfo.VADDump):
    """Displays process related information"""
    
    def __init__(self, config, *args, **kwargs):
        vadinfo.VADDump.__init__(self, config, *args, **kwargs)
        config.remove_option("BASE")    
    
    def update_proc_peb_info(self, psdata):
        self.proc_peb_info = {}
        # Builds a dictionary of process executable information from PEB
        for proc in psdata:
            pid = int(proc.UniqueProcessId)
            self.proc_peb_info[pid] = [proc, 
                                       pid, 
                                       proc.ImageFileName,
                                       int(proc.InheritedFromUniqueProcessId),
                                       str(proc.CreateTime)]
            if proc.Peb: 
                # gets process information for the process executable from PEB and updates the dictionary 
                mods = proc.get_load_modules()
                for mod in mods:
                    ext = os.path.splitext(str(mod.FullDllName))[1].lower()
                    if (ext == ".exe"):
                        proc_cmd_line = proc.Peb.ProcessParameters.CommandLine
                        proc_image_pathname = proc.Peb.ProcessParameters.ImagePathName
                        proc_image_baseaddr = proc.Peb.ImageBaseAddress
                        mod_baseaddr = mod.DllBase
                        mod_size = mod.SizeOfImage
                        mod_basename = mod.BaseDllName
                        mod_fullname = mod.FullDllName
                        break
                        
                self.proc_peb_info[pid].extend([str(proc_cmd_line),
                                                str(proc_image_pathname),
                                                Address(proc_image_baseaddr),
                                                Address(mod_baseaddr),
                                                Hex(mod_size),
                                                str(mod_basename),
                                                str(mod_fullname or "")])
                        
            else:
                self.proc_peb_info[pid].extend(["NoPEB",
                                                "NoPEB",
                                                Address(0),
                                                Address(0),
                                                Hex(0),
                                                "NoPEB",
                                                "NoPEB"])
                
                
    def update_proc_vad_info(self, proc_peb_info):
        """Builds a dictionary of process executable information from VAD"""
        self.proc_vad_info = {}
        for pid in proc_peb_info:
            self.proc_vad_info[pid] = []
            proc = proc_peb_info[pid][0]
            
            if proc.Peb:
                # gets process information for the process executable from VAD and updates the dictionary
                for vad, addr_space in proc.get_vads(vad_filter = proc._mapped_file_filter):
                    ext = ""
                    vad_found = False
                    if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = addr_space).e_magic != 0x5A4D:
                        continue
                    
                    if str(vad.FileObject.FileName or ''):
                        ext = os.path.splitext(str(vad.FileObject.FileName))[1].lower()
                    
                    if (ext == ".exe") or (vad.Start == proc.Peb.ImageBaseAddress):
                        vad_filename =  vad.FileObject.FileName
                        vad_baseaddr = vad.Start
                        vad_size = vad.End - vad.Start
                        vad_protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v())
                        vad_tag = vad.Tag
                        self.proc_vad_info[pid].extend([str(vad_filename or ''),
                                                        Address(vad_baseaddr),
                                                        Hex(vad_size), 
                                                        str(vad_protection or ''),
                                                        str(vad_tag or '')])
                        vad_found = True
                        break
                
                if vad_found == False:
                    self.proc_vad_info[pid].extend(["NA", Address(0), Hex(0), "NA", "NA"])
                          
            else:
                self.proc_vad_info[pid].extend(["NoVAD", Address(0), Hex(0), "NoVAD", "NoVAD"])
    
    def get_proc_peb_info(self):
        return self.proc_peb_info
    
    def get_proc_vad_info(self):
        return self.proc_vad_info
    
    def update_parent_proc_info(self, proc_peb_info):
        """Builds a dictionary containing parent process information for all the processes"""
        self.parent_proc_info = {}
        for pid in proc_peb_info:
            self.parent_proc_info[pid] = []
            if pid == 4:
                self.parent_proc_info[pid].extend(["", 0])
            else: 
                ppid = int(proc_peb_info[pid][3])
                if ppid in proc_peb_info:
                    ppname = str(proc_peb_info[ppid][2])
                else:
                    ppname = "NA"   
                self.parent_proc_info[pid].extend([ppname, ppid])                 
    
    def get_parent_proc_info(self):
        return self.parent_proc_info

    def calculate(self):
        if self._config.PID:
            filter_pid = self._config.PID
            # This is so that when -p option is given it can still enumerate all processes to determine parent
            self._config.PID = None
        else:
            filter_pid = None
        ps = PSList(self._config)
        psdata = ps.calculate()
        self.update_proc_peb_info(psdata)
        proc_peb_info = self.get_proc_peb_info()
        self.update_parent_proc_info(proc_peb_info)
        parent_proc_info = self.get_parent_proc_info()

        self.update_proc_vad_info(proc_peb_info)
        proc_vad_info = self.get_proc_vad_info()
        if not filter_pid:
            for pid in proc_peb_info:
                yield(proc_peb_info[pid], parent_proc_info[pid])
        else:
            for p in filter_pid.split(','):
                fil_pid = int(p)
                yield(proc_peb_info[fil_pid], parent_proc_info[fil_pid])
    
    def render_text(self, outfd, data):
        outfd.write("Process|ProcessFullName|PID|PPID|ImagePath|CmdLine(PEB)\n")

        for (proc_peb_info, parent_proc_info) in data:
            (proc, pid, proc_name, ppid, create_time, proc_cmd_line,
             proc_image_pathname, proc_image_baseaddr, mod_baseaddr,
             mod_size, mod_basename, mod_fullname) = proc_peb_info

            outfd.write("{0}|{1}|{2}|{3}|{4}|{5}\n".
                        format(proc_name, mod_basename, pid, ppid,proc_image_pathname,proc_cmd_line ))




