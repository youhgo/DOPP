#!/usr/bin/python3
import json
import os
import pathlib
import traceback
import argparse
import re
from datetime import datetime
import xmltodict
import time
import sys

from plaso.cli.logger import exception


# TODO : Parsing
# TODO : Parse Firewall Detection
# TODO : Parse Log erasure

# TODO : General
# TODO : Parse Task Scheduler event 4698 + 4702


class MaximumPlasoParserJson:
    """
       Class MaximumPlasoParser
       MPP or MaximumPlasoParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, dir_out, output_type="csv", separator="|", case_name=None, config_file=None,
                 machine_name="workstation") -> None:
        """
        Constructor for the MaximumPlasoParser Class

        :param dir_out: (str) directory where the results file will be written
        :param output_type: (str) output format, can be csv or json
        :param separator: (str) separator for csv output file
        :param case_name:  (str) name that will be set into json result files (for practical purpose with elk)
        :param config_file: (str) full path to a json file containing a configuration
        """

        self.dir_out = dir_out
        self.output_type = output_type
        self.separator = separator
        self.case_name = case_name
        self.machine_name = machine_name

        self.current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.work_dir = os.path.join(os.path.abspath(dir_out), "mpp_{}_{}".format(self.machine_name, self.current_date))
        self.initialise_working_directories()

        if config_file:
            self.config = self.read_json_config(config_file)
        else:
            self.config = {
                "user_logon_id4624": 1,
                "user_failed_logon_id4625": 1,
                "user_special_logon_id4672": 1,
                "user_explicit_logon_id4648": 1,
                "new_proc_file_id4688": 1,
                "windows_Start_Stop": 1,
                "task_scheduler": 1,
                "remote_rdp": 1,
                "local_rdp": 1,
                "bits": 1,
                "service": 1,
                "powershell": 1,
                "powershell_script": 1,
                "wmi": 1,
                "app_exp": 1,
                "amcache": 1,
                "app_compat": 1,
                "sam": 1,
                "user_assist": 1,
                "mru": 1,
                "ff_history": 1,
                "prefetch": 1,
                "srum": 1,
                "run": 1,
                "lnk": 1,
                "mft": 1,
                "windefender": 1,
                "timeline": 1
            }

        self.d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }
        self.d_regex_aterfact_by_file_name = {
            "security": re.compile(r'((s|S)ecurity\.evtx|(s|S)ecurity\.evt)'),
            "system": re.compile(r'((s|S)ystem\.evtx|(s|S)ystem\.evt)'),
            "taskScheduler": re.compile(r'.*TaskScheduler%4Operational\.evtx'),
            "bits": re.compile(r'.*Bits-Client%4Operational\.evtx'),
            "rdp_local": re.compile(r'.*TerminalServices-LocalSessionManager%4Operational\.evtx'),
            "rdp_remot": re.compile(r'.*TerminalServices-RemoteConnectionManager%4Operational\.evtx'),
            "powershell": re.compile(
                r'(.*Microsoft-Windows-PowerShell%4Operational\.evtx)|(.*Windows_PowerShell\.evtx)'),
            "wmi": re.compile(r'.*Microsoft-Windows-WMI-Activity%4Operational\.evtx'),
            "application_experience": re.compile(
                r'.*Microsoft-Windows-Application-Experience%4Program-Telemetry\.evtx'),
            "amcache": re.compile(r'.*(A|a)mcache\.hve'),
            "appCompat": re.compile(r'.*(A|a)mcache\.hve')
        }
        self.d_regex_artefact_by_source_name = {
            "security": re.compile(r'Microsoft-Windows-Security-Auditing'),
            "system": re.compile(r'Service Control Manager'),
            "taskScheduler": re.compile(r'Microsoft-Windows-TaskScheduler'),
            "bits": re.compile(r'Microsoft-Windows-Bits-Client'),
            "rdp_local": re.compile(r'Microsoft-Windows-TerminalServices-LocalSessionManager'),
            "rdp_remote": re.compile(r'Microsoft-Windows-TerminalServices-RemoteConnectionManager'),
            "powershell": re.compile(r'(Microsoft-Windows-PowerShell)|(PowerShell)'),
            "wmi": re.compile(r'Microsoft-Windows-WMI-Activity'),
            "application_experience": re.compile(r'Microsoft-Windows-Application-Experience'),
            "windefender": re.compile(r'Microsoft-Windows-Windows Defender')
            # .*Microsoft-Windows-Windows_Defender%4Operational
        }
        self.d_regex_artefact_by_parser_name = {
            "amcache": re.compile(r'amcache'),
            "appCompat": re.compile(r'appcompatcache'),
            "sam": re.compile(r'windows_sam_users'),
            "userassist": re.compile(r'userassist'),
            "mru": re.compile(r'(bagmru)|(mru)'),
            "ff_history": re.compile(r'firefox_history'),
            "prefetch": re.compile(r'prefetch'),
            "lnk": re.compile(r'lnk'),
            "srum": re.compile(r'srum'),
            "run": re.compile(r'windows_run'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }

        self.l_csv_header_timeline = ["Date", "Time", "SourceArtefact", "Other"]
        self.l_csv_header_4624 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4625 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4672 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4648 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4688 = ["Date", "Time", "event_code", "subject_user_name", "target_user_name",
                                  "parent_process_name", "new_process_name", "command_line"]
        self.l_csv_header_tscheduler = ["Date", "Time", "event_code", "name", "task_name", "instance_id",
                                        "action_name", "result_code", "user_name", "user_context"]
        self.l_csv_header_remot_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr"]
        self.l_csv_header_local_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr", "session_id",
                                       "source", "target_session", "reason_n", "reason"]
        self.l_csv_header_bits = ["Date", "Time", "event_code", "id", "job_id", "job_title", "job_owner",
                                  "user", "bytes_total", "bytes_transferred", "file_count", "file_length", "file_Time",
                                  "name", "url", "process_path"]
        self.l_csv_header_7045 = ["Date", "Time", "event_code", "account_name", "img_path", "service_name",
                                  "start_type"]
        self.l_csv_header_powershell = ["Date", "Time", "event_code", "path_to_script", "script_block_text"]
        self.l_csv_header_script_powershell = ["Date", "Time", "event_code", "cmd"]
        self.l_csv_header_wmi = ["Date", "Time", "user", "nameSpace", "Query"]
        self.l_csv_header_app_exp = ["Date", "Time", "ExePath", "FixName", "Query"]
        self.l_csv_header_amcache = ["Date", "Time", "Name", "FullPath", "id", "Hash"]
        self.l_csv_header_appcompat = ["Date", "Time", "Name", "FullPath", "Hash"]
        self.l_csv_header_sam = ["Date", "Time", "username", "login_count"]
        self.l_csv_header_usserassit = ["Date", "Time", "valueName", "appFocus", "appDuration"]
        self.l_csv_header_mru = ["Date", "Time", "entries"]
        self.l_csv_header_srum = ["Date", "Time", "description"]
        self.l_csv_header_run = ["Date", "Time", "entrie"]
        self.l_csv_header_ff_history = ["Date", "Time", "url", "visit_count", "visit_type", "isType", "from_visit"]
        self.l_csv_header_ie_history = ["Date", "Time", "url", "visit_count", "visit_type", "isType", "from_visit"]
        self.l_csv_header_prefetch = ["Date", "Time", "name", "path", "nbExec", "sha256"]
        self.l_csv_header_lnk = ["Date", "Time", "description", "working_dir"]
        self.l_csv_header_mft = ["Date", "Time", "source","fileType", "action", "fileName"]
        self.l_csv_header_windefender = ["Date", "Time", "Event", "ThreatName", "Severity", "User", "ProcessName",
                                         "Path", "Action"]
        self.l_csv_header_start_stop = ["Date", "Time", "message"]

        self.timeline_file_csv = ""
        self.logon_res_file_csv = ""
        self.logon_failed_file_csv = ""
        self.logon_spe_file_csv = ""
        self.logon_exp_file_csv = ""
        self.new_proc_file_csv = ""
        self.task_scheduler_file_csv = ""
        self.remote_rdp_file_csv = ""
        self.local_rdp_file_csv = ""
        self.bits_file_csv = ""
        self.service_file_csv = ""
        self.powershell_file_csv = ""
        self.powershell_script_file_csv = ""
        self.wmi_file_csv = ""
        self.app_exp_file_csv = ""
        self.amcache_res_file_csv = ""
        self.app_compat_res_file_csv = ""
        self.sam_res_file_csv = ""
        self.user_assist_file_csv = ""
        self.mru_res_file_csv = ""
        self.ff_history_res_file_csv = ""
        self.ie_history_res_file_csv = ""
        self.prefetch_res_file_csv = ""
        self.srum_res_file_csv = ""
        self.run_res_file_csv = ""
        self.lnk_res_file_csv = ""

        self.mft_res_file_csv = ""

        self.windefender_res_file_csv = ""

        self.windows_start_stop_res_file_csv = ""

        self.timeline_file_json = ""
        self.logon_res_file_json = ""
        self.logon_failed_file_json = ""
        self.logon_spe_file_json = ""
        self.logon_exp_file_json = ""
        self.new_proc_file_json = ""
        self.task_scheduler_file_json = ""
        self.remote_rdp_file_json = ""
        self.local_rdp_file_json = ""
        self.bits_file_json = ""
        self.service_file_json = ""
        self.powershell_file_json = ""
        self.powershell_script_file_json = ""
        self.wmi_file_json = ""
        self.app_exp_file_json = ""
        self.amcache_res_file_json = ""
        self.app_compat_res_file_json = ""
        self.sam_res_file_json = ""
        self.user_assist_file_json = ""
        self.mru_res_file_json = ""
        self.ff_history_res_file_json = ""
        self.ie_history_res_file_json = ""
        self.prefetch_res_file_json = ""
        self.srum_res_file_json = ""
        self.run_res_file_json = ""
        self.lnk_res_file_json = ""

        self.mft_res_file_json = ""

        self.windefender_res_file_json = ""

        self.windows_start_stop_res_file_json = ""

        self.initialise_results_files()

    def initialise_working_directories(self):
        """
        To create directories where the results will be written
        :return:
        """
        try:
            # print("creating {}".format(self.work_dir))
            os.makedirs(self.work_dir, exist_ok=True)
            print("result directory is located at : {}".format(self.work_dir))
        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

    @staticmethod
    def read_json_config(path_to_config):
        """
        Function to read and load a json file into a dict
        :param path_to_config: (str) full path to a json file
        :return: (dict) dict containing the content of the json file
        """
        with open(path_to_config, 'r') as config:
            return json.load(config)

    @staticmethod
    def convert_epoch_to_date(epoch_time):
        """
        Function to convert an epoch time (nanoseconds) into date and time.
        Split into 2 variable date and time
        :param epoch_time: (int) epoch time to be converted
        :return:
        (str) date in format %Y-%m-%d
        (str) time in format %H:%M:%S
        """
        dt = datetime.fromtimestamp(epoch_time / 1000000).strftime('%Y-%m-%dT%H:%M:%S.%f')
        l_dt = dt.split("T")
        return l_dt[0], l_dt[1]

    def initialise_result_file_csv(self, header, file_name, extension="csv"):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param header: (list[str]) list containing all column name
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.work_dir, "{}.{}".format(file_name, extension)), 'a')
        result_file_stream.write(self.separator.join(header))
        result_file_stream.write("\n")
        return result_file_stream

    def initialise_result_file_json(self, file_name, extension="json"):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.work_dir, "{}.{}".format(file_name, extension)), 'a')
        return result_file_stream

    def initialise_results_files(self):
        if self.output_type in ["all", "csv"]:
            self.initialise_results_files_csv()
        if self.output_type in ["all", "json"]:
            self.initialise_results_files_json()

    def initialise_results_files_csv(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """


        if self.config.get("user_logon_id4624", 0):
            self.logon_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_4624, "4624usrLogon")

        if self.config.get("user_failed_logon_id4625", 0):
            self.logon_failed_file_csv = self.initialise_result_file_csv(self.l_csv_header_4625,
                                                                         "4625usrFailLogon")
        if self.config.get("user_special_logon_id4672", 0):
            self.logon_spe_file_csv = self.initialise_result_file_csv(self.l_csv_header_4672,
                                                                      "4672usrSpeLogon")
        if self.config.get("user_explicit_logon_id4648", 0):
            self.logon_exp_file_csv = self.initialise_result_file_csv(self.l_csv_header_4648,
                                                                      "4648usrExpLogon")
        if self.config.get("new_proc_file_id4688", 0):
            self.new_proc_file_csv = self.initialise_result_file_csv(self.l_csv_header_4688,
                                                                     "4688newProc")
        if self.config.get("windows_Start_Stop", 0):
            self.windows_start_stop_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_start_stop,
                                                                                   "winStartStop")
        if self.config.get("task_scheduler", 0):
            self.task_scheduler_file_csv = self.initialise_result_file_csv(self.l_csv_header_tscheduler,
                                                                           "taskScheduler")

        if self.config.get("remote_rdp", 0):
            self.remote_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_remot_rdp,
                                                                       "rdpRemote")

        if self.config.get("local_rdp", 0):
            self.local_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_local_rdp,
                                                                      "rdpLocal")
        if self.config.get("bits", 0):
            self.bits_file_csv = self.initialise_result_file_csv(self.l_csv_header_bits, "bits")

        if self.config.get("service", 0):
            self.service_file_csv = self.initialise_result_file_csv(self.l_csv_header_7045, "7045newService")

        if self.config.get("powershell", 0):
            self.powershell_file_csv = self.initialise_result_file_csv(self.l_csv_header_powershell,
                                                                       "powershell")
        if self.config.get("powershell_script", 0):
            self.powershell_script_file_csv = self.initialise_result_file_csv(self.l_csv_header_script_powershell,
                                                                              "powershellScript")

        if self.config.get("wmi", 0):
            self.wmi_file_csv = self.initialise_result_file_csv(self.l_csv_header_wmi, "wmi")

        # ----------------------------- Hives ------------------------------------------------

        if self.config.get("app_exp"):
            self.app_exp_file_csv = self.initialise_result_file_csv(self.l_csv_header_app_exp,
                                                                    "applicationExperience")

        if self.config.get("amcache"):
            self.amcache_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_amcache, "amcache")

        if self.config.get("app_compat"):
            self.app_compat_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_appcompat,
                                                                           "shimcache")

        if self.config.get("sam"):
            self.sam_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_sam, "sam")

        if self.config.get("user_assist"):
            self.user_assist_file_csv = self.initialise_result_file_csv(self.l_csv_header_usserassit, "usrAssist")

        if self.config.get("mru"):
            self.mru_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_mru, "mru")

        if self.config.get("srum"):
            self.srum_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_srum, "srum")

        if self.config.get("run"):
            self.run_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_run, "runKey")

        # ----------------------------- Other ------------------------------------------------

        if self.config.get("ff_history"):
            self.ff_history_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_ff_history, "ffHistory")

        if self.config.get("ie_history"):
            self.ie_history_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_ie_history, "ieHistory")

        if self.config.get("prefetch"):
            self.prefetch_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_prefetch, "prefetch")

        if self.config.get("lnk"):
            self.lnk_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_lnk, "lnk")

        if self.config.get("mft"):
            self.mft_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_mft, "mft")

        if self.config.get("windefender"):
            self.windefender_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_windefender,
                                                                            "windefender")

    def initialise_results_files_json(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

        if self.config.get("user_logon_id4624", 0):
            self.logon_res_file_json = self.initialise_result_file_json("user_logon_id4624")

        if self.config.get("user_failed_logon_id4625", 0):
            self.logon_failed_file_json = self.initialise_result_file_json("user_failed_logon_id4625")

        if self.config.get("user_special_logon_id4672", 0):
            self.logon_spe_file_json = self.initialise_result_file_json("user_special_logon_id4672")

        if self.config.get("user_explicit_logon_id4648", 0):
            self.logon_exp_file_json = self.initialise_result_file_json("user_explicit_logon_id4648")

        if self.config.get("new_proc_file_id4688", 0):
            self.new_proc_file_json = self.initialise_result_file_json("new_proc_file_id4688")

        if self.config.get("windows_Start_Stop", 0):
            self.windows_start_stop_res_file_json = self.initialise_result_file_json("windows_start_stop")

        if self.config.get("task_scheduler", 0):
            self.task_scheduler_file_json = self.initialise_result_file_json("task_scheduler")

        if self.config.get("remote_rdp", 0):
            self.remote_rdp_file_json = self.initialise_result_file_json("remote_rdp")

        if self.config.get("local_rdp", 0):
            self.local_rdp_file_json = self.initialise_result_file_json("local_rdp")

        if self.config.get("bits", 0):
            self.bits_file_json = self.initialise_result_file_json("bits")

        if self.config.get("service", 0):
            self.service_file_json = self.initialise_result_file_json("7045")

        if self.config.get("powershell", 0):
            self.powershell_file_json = self.initialise_result_file_json("powershell")

        if self.config.get("powershell_script", 0):
            self.powershell_script_file_json = self.initialise_result_file_json("powershell_script")

        if self.config.get("wmi", 0):
            self.wmi_file_json = self.initialise_result_file_json("wmi")

        # ----------------------------- Hives ------------------------------------------------

        if self.config.get("app_exp"):
            self.app_exp_file_json = self.initialise_result_file_json("application_experience")

        if self.config.get("amcache"):
            self.amcache_res_file_json = self.initialise_result_file_json("amcache")

        if self.config.get("app_compat"):
            self.app_compat_res_file_json = self.initialise_result_file_json("app_compat_cache")
        if self.config.get("sam"):
            self.sam_res_file_json = self.initialise_result_file_json("sam")

        if self.config.get("user_assist"):
            self.user_assist_file_json = self.initialise_result_file_json("user_assist")

        if self.config.get("mru"):
            self.mru_res_file_json = self.initialise_result_file_json("mru")

        if self.config.get("srum"):
            self.srum_res_file_json = self.initialise_result_file_json("srum")

        if self.config.get("run"):
            self.run_res_file_json = self.initialise_result_file_json("run_key")

        # ----------------------------- Other ------------------------------------------------

        if self.config.get("ff_history"):
            self.ff_history_res_file_json = self.initialise_result_file_json("ff_history")

        if self.config.get("ie_history"):
            self.ie_history_res_file_json = self.initialise_result_file_json("ie_history")

        if self.config.get("prefetch"):
            self.prefetch_res_file_json = self.initialise_result_file_json("prefetch")

        if self.config.get("lnk"):
            self.lnk_res_file_json = self.initialise_result_file_json("lnk")

        if self.config.get("mft"):
            self.mft_res_file_json = self.initialise_result_file_json("mft")

        if self.config.get("windefender"):
            self.windefender_res_file_json = self.initialise_result_file_json("windefender")

    def identify_type_artefact_by_parser(self, line):
        """
        Function to indentify an artefact type depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        for key, value in self.d_regex_type_artefact.items():
            if re.search(value, line.get("parser")):
                return key

    def identify_artefact_by_filename(self, line):
        """
        Function to indentify an artefact type depending on the name of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the filename
        """
        for key, value in self.d_regex_aterfact_by_file_name.items():
            if re.search(value, line.get("filename")):
                return key

    def identify_artefact_by_source_name(self, line):
        """
        Function to indentify an artefact type depending on the source type of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the source name
        """
        for key, value in self.d_regex_artefact_by_source_name.items():
            if re.search(value, line.get("source_name")):
                return key

    def identify_artefact_by_parser_name(self, line):
        """
        Function to indentify an artefact depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        for key, value in self.d_regex_artefact_by_parser_name.items():
            if re.search(value, line.get("parser")):
                return key

    def assign_parser(self, line, type_artefact):
        """
        Function to assign a parser depending on the artefact type
        :param line: (dict) dict containing one line of the plaso timeline,
        :param type_artefact: (str) type of artefact
        :return: None
        """
        # print('type artefact is {}'.format(type_artefact))
        if type_artefact == "evtx":
            self.parse_logs(line)
        if type_artefact == "hive":
            self.parse_hives(line)
        if type_artefact == "db":
            self.parse_db(line)
        if type_artefact == "winFile":
            self.parse_win_file(line)
        if type_artefact == "mft":
            self.parse_mft(line)

    def close_files_leg(self):
        """
        Function to close all opened stream
        :return:
        """
        self.timeline_file_csv.close()
        self.logon_res_file.close()
        self.logon_failed_file.close()
        self.logon_spe_file.close()
        self.new_proc_file.close()
        self.logon_exp_file.close()
        self.task_scheduler_file.close()
        self.remote_rdp_file.close()
        self.local_rdp_file.close()
        self.bits_file.close()
        self.service_file.close()
        self.powershell_file.close()
        self.powershell_script_file.close()
        self.wmi_file.close()
        self.app_exp_file.close()

        self.amcache_res_file.close()
        self.app_compat_res_file.close()
        self.sam_res_file.close()
        self.user_assist_file.close()
        self.srum_res_file.close()
        self.run_res_file.close()

        self.ff_history_res_file.close()
        self.ie_history_res_file.close()

        self.prefetch_res_file.close()
        self.lnk_res_file.close()
        self.mft_res_file.close()

    def close_files(self):
        if self.output_type in ["all", "csv"]:
            self.close_files_csv()
        if self.output_type in ["all", "json"]:
            self.close_files_json()

    def close_files_csv(self):
        """
        Function to close all opened stream
        :return:
        """

        if self.logon_res_file_csv:
            self.logon_res_file_csv.close()
        if self.logon_failed_file_csv:
            self.logon_failed_file_csv.close()
        if self.logon_spe_file_csv:
            self.logon_spe_file_csv.close()
        if self.logon_exp_file_csv:
            self.logon_exp_file_csv.close()
        if self.windows_start_stop_res_file_csv:
            self.windows_start_stop_res_file_csv.close()
        if self.task_scheduler_file_csv:
            self.task_scheduler_file_csv.close()
        if self.remote_rdp_file_csv:
            self.remote_rdp_file_csv.close()
        if self.local_rdp_file_csv:
            self.local_rdp_file_csv.close()
        if self.bits_file_csv:
            self.bits_file_csv.close()
        if self.service_file_csv:
            self.service_file_csv.close()
        if self.powershell_file_csv:
            self.powershell_file_csv.close()
        if self.powershell_script_file_csv:
            self.powershell_script_file_csv.close()
        if self.wmi_file_csv:
            self.wmi_file_csv.close()
        if self.app_exp_file_csv:
            self.app_exp_file_csv.close()

        if self.amcache_res_file_csv:
            self.amcache_res_file_csv.close()
        if self.app_compat_res_file_csv:
            self.app_compat_res_file_csv.close()
        if self.sam_res_file_csv:
            self.sam_res_file_csv.close()
        if self.user_assist_file_csv:
            self.user_assist_file_csv.close()
        if self.srum_res_file_csv:
            self.srum_res_file_csv.close()
        if self.run_res_file_csv:
            self.run_res_file_csv.close()

        if self.ff_history_res_file_csv:
            self.ff_history_res_file_csv.close()
        if self.ie_history_res_file_csv:
            self.ie_history_res_file_csv.close()
        if self.prefetch_res_file_csv:
            self.prefetch_res_file_csv.close()
        if self.lnk_res_file_csv:
            self.lnk_res_file_csv.close()
        if self.mft_res_file_csv:
            self.mft_res_file_csv.close()

    def close_files_json(self):
        """
        Function to close all opened stream
        :return:
        """
        if self.logon_res_file_json:
            self.logon_res_file_json.close()
        if self.logon_failed_file_json:
            self.logon_failed_file_json.close()
        if self.logon_spe_file_json:
            self.logon_spe_file_json.close()
        if self.logon_exp_file_json:
            self.logon_exp_file_json.close()
        if self.windows_start_stop_res_file_json:
            self.windows_start_stop_res_file_json.close()
        if self.task_scheduler_file_json:
            self.task_scheduler_file_json.close()
        if self.remote_rdp_file_json:
            self.remote_rdp_file_json.close()
        if self.local_rdp_file_json:
            self.local_rdp_file_json.close()
        if self.bits_file_json:
            self.bits_file_json.close()
        if self.service_file_json:
            self.service_file_json.close()
        if self.powershell_file_json:
            self.powershell_file_json.close()
        if self.powershell_script_file_json:
            self.powershell_script_file_json.close()
        if self.wmi_file_json:
            self.wmi_file_json.close()
        if self.app_exp_file_json:
            self.app_exp_file_json.close()

        if self.amcache_res_file_json:
            self.amcache_res_file_json.close()
        if self.app_compat_res_file_json:
            self.app_compat_res_file_json.close()
        if self.sam_res_file_json:
            self.sam_res_file_json.close()
        if self.user_assist_file_json:
            self.user_assist_file_json.close()
        if self.srum_res_file_json:
            self.srum_res_file_json.close()
        if self.run_res_file_json:
            self.run_res_file_json.close()

        if self.ff_history_res_file_json:
            self.ff_history_res_file_json.close()
        if self.ie_history_res_file_json:
            self.ie_history_res_file_json.close()
        if self.prefetch_res_file_json:
            self.prefetch_res_file_json.close()
        if self.lnk_res_file_json:
            self.lnk_res_file_json.close()
        if self.mft_res_file_json:
            self.mft_res_file_json.close()

    def parse_timeline(self, path_to_tl):
        """
        Main function to parse the plaso timeline
        :param path_to_tl: (str) full path to the timeline
        :return: None
        """
        try:
            with open(path_to_tl) as timeline:
                for line in timeline:
                    try:
                        d_line = json.loads(line)
                    except:
                        print("could not load json line, skiping line")
                        print(traceback.format_exc())
                        continue
                    type_artefact = self.identify_type_artefact_by_parser(d_line)
                    if type_artefact:
                        self.assign_parser(d_line, type_artefact)

            self.close_files()
            self.clean_duplicates(self.work_dir)
            if self.config.get("timeline", 0):
                self.create_timeline()

        except Exception as ex:
            print("error with parsing")
            print("error is {}".format(traceback.format_exc()))
            self.close_files()

    #  -------------------------------------------------------------  Logs ---------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_logs(self, line):
        """
        Main function to parse log type artefacts
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        log_type = self.identify_artefact_by_source_name(line)
        if log_type == "security":
            self.parse_security_evtx(line)
        if log_type == "taskScheduler":
            self.parse_task_scheduler(line)
        if log_type == "bits":
            self.parse_bits(line)
        if log_type == "system":
            self.parse_system_evtx(line)
        if log_type == "rdp_local":
            self.parse_rdp_local(line)
        if log_type == "rdp_remote":
            self.parse_rdp_remote(line)
        if log_type == "powershell":
            self.parse_powershell(line)
        if log_type == "wmi":
            self.parse_wmi(line)
        if log_type == "application_experience":
            self.parse_app_experience(line)
        if log_type == "windefender":
            self.parse_windows_defender(line)

    #  ----------------------------------------  Wmi ---------------------------------------------
    def parse_wmi(self, event):
        """
        Main function to parse wmi type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.wmi_file_csv or self.wmi_file_json:
            if str(event_code) in ["5860", "5861"]:
                self.parse_wmi_evtx_from_xml(event)
            if str(event_code) in ["5858"]:
                self.parse_wmi_failure_from_xml(event)

    def parse_wmi_evtx_from_xml(self, event):
        """
        Function to parse wmi log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {})

        operation_name = list(event_data.keys())[0]
        op_dict = event_data.get(operation_name, {})
        namespace = op_dict.get("NamespaceName", "-")
        user = op_dict.get("User", "-")
        cause = op_dict.get("PossibleCause", "-").replace("\n", "")
        query = op_dict.get("Query", "-").replace("\n", "")
        consumer = op_dict.get("CONSUMER", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              operation_name, self.separator,
                                                              user, self.separator,
                                                              namespace, self.separator,
                                                              consumer, self.separator,
                                                              cause, self.separator,
                                                              query)

            self.wmi_file_csv.write(res)
            self.wmi_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "operation_name": operation_name,
                "user": user,
                "namespace": namespace,
                "consumer": consumer,
                "cause": cause,
                "query": query,
                "Artefact": "WMI"
            }
            json.dump(res, self.wmi_file_json)
            self.wmi_file_json.write('\n')

    def parse_wmi_failure_from_xml(self, event):
        """
        Function to parse wmi failure log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {})

        operation_name = list(event_data.keys())[0]
        op_dict = event_data.get(operation_name, {})
        namespace = op_dict.get("NamespaceName", "-")
        user = op_dict.get("User", "-")
        cause = op_dict.get("PossibleCause", "-").replace("\n", "")
        query = op_dict.get("Operation", "-").replace("\n", "")
        consumer = op_dict.get("CONSUMER", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              operation_name, self.separator,
                                                              user, self.separator,
                                                              namespace, self.separator,
                                                              consumer, self.separator,
                                                              cause, self.separator,
                                                              query)

            self.wmi_file_csv.write(res)
            self.wmi_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "operation_name": operation_name,
                "user": user,
                "namespace": namespace,
                "consumer": consumer,
                "cause": cause,
                "query": query,
                "Artefact": "WMI"
            }
            json.dump(res, self.wmi_file_json)
            self.wmi_file_json.write('\n')

    #  ----------------------------------------  RDP ---------------------------------------------
    def parse_rdp_local(self, event):
        """
        Main function to parse rdp local type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.local_rdp_file_csv or self.local_rdp_file_json:
            if str(event_code) in ["21", "24", "25", "39", "40"]:
                self.parse_rdp_local_evtx_from_xml(event)

    def parse_rdp_remote(self, event):
        """
        Main function to parse rdp remot type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.remote_rdp_file_csv or self.remote_rdp_file_json:
            if str(event_code) in ["1149"]:
                self.parse_rdp_remote_evtx_from_xml(event)

    def parse_rdp_remote_evtx_from_xml(self, event):
        """
        Function to parse remote rdp log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", {})

        event_code = event.get("event_identifier")
        user_name = event_data.get("Param1", "-")
        ip_addr = event_data.get("Param3", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}InitConnexion{}{}{}{}".format(ts_date, self.separator,
                                                             ts_time, self.separator,
                                                             event_code, self.separator,
                                                             self.separator,
                                                             user_name, self.separator,
                                                             ip_addr)
            self.remote_rdp_file_csv.write(res)
            self.remote_rdp_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "user_name": user_name,
                "ip_address": ip_addr,
                "Artefact": "EVTX_REMOTE_RDP"
            }
            json.dump(res, self.remote_rdp_file_json)
            self.remote_rdp_file_json.write('\n')

    def parse_rdp_local_evtx_from_xml(self, event):
        """
        Function to parse local rdp log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", [])
        event_code = str(event.get("event_identifier"))
        user_name = event_data.get("User", "-")
        ip_addr = event_data.get("Adress", "-")
        session_id = event_data.get("SessionID", "-")
        source = event_data.get("Source", '-')
        reason_n = event_data.get("Reason", "-")
        target_session = event_data.get("", "-")

        if event_code == "21":
            reason = "AuthSuccess"
        elif event_code == "24":
            reason = "UserDisconnected"
        elif event_code == "25":
            reason = "UserReconnected"
        elif event_code == "39":
            reason = "UserHasBeenDisconnected"
        elif event_code == "40":
            reason = "UserHasBeenDisconnected"
        else:
            reason = "-"

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                                  ts_time, self.separator,
                                                                  event_code, self.separator,
                                                                  user_name, self.separator,
                                                                  ip_addr, self.separator,
                                                                  session_id, self.separator,
                                                                  source, self.separator,
                                                                  target_session, self.separator,
                                                                  reason_n, self.separator,
                                                                  reason)
            self.local_rdp_file_csv.write(res)
            self.local_rdp_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "user_name": user_name,
                "ip_address": ip_addr,
                "session_id": session_id,
                "source": source,
                "target_session": target_session,
                "reason_n": reason_n,
                "reason": reason,
                "Artefact": "EVTX_LOCAL_RDP"
            }
            json.dump(res, self.local_rdp_file_json)
            self.local_rdp_file_json.write('\n')

    #  ----------------------------------------  Bits ---------------------------------------------

    def parse_bits(self, event):
        """
        Main function to parse bits type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if self.bits_file_csv or self.bits_file_json:
            event_code = event.get("event_identifier")
            if str(event_code) in ["3", "4", "59", "60", "61"]:
                self.parse_bits_evtx_from_xml(event)

    def parse_bits_evtx_from_xml(self, event):
        """
        Function to parse remote bits log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        user = "-"
        identifiant = "-"
        job_owner = "-"
        job_id = "-"
        job_title = "-"
        bytes_total = "-"
        bytes_transferred = "-"
        file_count = "-"
        file_length = "-"
        file_time = "-"
        name = "-"
        url = "-"
        process_path = "-"

        for data in event_data:
            if data.get("@Name", "") == "User":
                user = data.get("#text", "-")

            elif data.get("@Name", "") == "Id":
                identifiant = data.get("#text", "-")

            elif data.get("@Name", "") == "jobOwner":
                job_owner = data.get("#text", "-")

            elif data.get("@Name", "") == "jobId":
                job_id = data.get("#text", "-")

            elif data.get("@Name", "") == "jobTitle":
                job_title = data.get("#text", "-")

            elif data.get("@Name", "") == "bytesTotal":
                bytes_total = data.get("#text", "-")

            elif data.get("@Name", "") == "bytesTransferred":
                bytes_transferred = data.get("#text", "-")

            elif data.get("@Name", "") == "fileCount":
                file_count = data.get("#text", "-")

            elif data.get("@Name", "") == "fileLength":
                file_length = data.get("#text", "-")

            elif data.get("@Name", "") == "fileTime":
                file_time = data.get("#text", "-")

            elif data.get("@Name", "") == "name":
                name = data.get("#text", "-")

            elif data.get("@Name", "") == "url":
                url = data.get("#text", "-")

            elif data.get("@Name", "") == "processPath":
                process_path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                                                          ts_time, self.separator,
                                                                                          event_code, self.separator,
                                                                                          identifiant, self.separator,
                                                                                          job_id, self.separator,
                                                                                          job_title, self.separator,
                                                                                          job_owner, self.separator,
                                                                                          user, self.separator,
                                                                                          bytes_total, self.separator,
                                                                                          bytes_transferred,
                                                                                          self.separator,
                                                                                          file_count, self.separator,
                                                                                          file_length, self.separator,
                                                                                          file_time, self.separator,
                                                                                          name, self.separator,
                                                                                          url, self.separator,
                                                                                          process_path)
            self.bits_file_csv.write(res)
            self.bits_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "identifiant": identifiant,
                "job_id": job_id,
                "job_title": job_title,
                "job_owner": job_owner,
                "user": bytes_total,
                "bytes_transferred": bytes_transferred,
                "file_count": file_count,
                "file_length": file_length,
                "file_time": file_time,
                "name": name,
                "url": url,
                "process_path": process_path,
                "Artefact": "BITS"
            }
            json.dump(res, self.bits_file_json)
            self.bits_file_json.write('\n')

    #  ----------------------------------------  Security ---------------------------------------------

    def parse_security_evtx(self, event):
        """
        Main function to parse security type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if event_code == 4624:
            if self.logon_res_file_csv or self.logon_res_file_json:
                self.parse_logon_from_xml(event)

        if event_code == 4625:
            if self.logon_failed_file_csv or self.logon_failed_file_json:
                self.parse_failed_logon_from_xml(event)

        if event_code == 4672:
            if self.logon_spe_file_csv or self.logon_spe_file_json:
                self.parse_spe_logon_from_xml(event)

        if event_code == 4648:
            if self.logon_exp_file_csv or self.logon_exp_file_json:
                self.parse_logon_exp_from_xml(event)

        if event_code == 4688:
            if self.new_proc_file_csv or self.new_proc_file_json:
                self.parse_new_proc_from_xml(event)

        if event_code == 4608 or event_code == 4609:
            if self.windows_start_stop_res_file_csv or self.windows_start_stop_res_file_json:
                self.parse_windows_startup_shutdown(event)

    def parse_logon_from_xml(self, event):
        """
        Function to parse logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4624"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"
        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type)
            self.logon_res_file_csv.write(res)
            self.logon_res_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_res_file_json)
            self.logon_res_file_json.write('\n')

    def parse_failed_logon_from_xml(self, event):
        """
        Function to parse failed logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4625"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type)
            self.logon_failed_file_csv.write(res)
            self.logon_failed_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_failed_file_json)
            self.logon_failed_file_json.write('\n')

    def parse_spe_logon_from_xml(self, event):
        """
        Function to parse special logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4672"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type)
            self.logon_spe_file_csv.write(res)
            self.logon_spe_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_spe_file_json)
            self.logon_spe_file_json.write('\n')

    def parse_logon_exp_from_xml(self, event):
        """
        Function to explicit logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4648"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type)
            self.logon_exp_file_csv.write(res)
            self.logon_exp_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_exp_file_json)
            self.logon_exp_file_json.write('\n')

    def parse_new_proc_from_xml(self, event):
        """
        Function to parse new process log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4688"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        cmd_line = "-"
        new_proc_name = "-"
        parent_proc_name = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "CommandLine":
                cmd_line = data.get("#text", "-")
            elif data.get("@Name", "") == "NewProcessName":
                new_proc_name = data.get("#text", "-")
            elif data.get("@Name", "") == "ParentProcessName":
                parent_proc_name = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          parent_proc_name, self.separator,
                                                          new_proc_name, self.separator,
                                                          cmd_line)
            self.new_proc_file_csv.write(res)
            self.new_proc_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "new_process_name": new_proc_name,
                "parent_process_name": parent_proc_name,
                "cmd_line": cmd_line,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.new_proc_file_json)
            self.new_proc_file_json.write('\n')

    #  ----------------------------------------  System ---------------------------------------------
    def parse_system_evtx(self, event):
        """
        Main function to parse system type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if event_code == 7045:
            if self.service_file_csv or self.service_file_json:
                self.parse_service_from_xml(event)

    def parse_service_from_xml(self, event):
        """
        Function to parse service creation log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        account_name = "-"
        img_path = "-"
        service_name = "-"
        start_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "AccountName":
                account_name = data.get("#text", "-")

            elif data.get("@Name", "") == "ImagePath":
                img_path = data.get("#text", "-")

            elif data.get("@Name", "") == "ServiceName":
                service_name = data.get("#text", "-")

            elif data.get("@Name", "") == "StartType":
                start_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  event_code, self.separator,
                                                  account_name, self.separator,
                                                  img_path, self.separator,
                                                  service_name, self.separator,
                                                  start_type)

            self.service_file_csv.write(res)
            self.service_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "account_name": account_name,
                "imgage_path": img_path,
                "service_name": service_name,
                "start_type": start_type,
                "Artefact": "EVTX_SYSTEM"
            }
            json.dump(res, self.service_file_json)
            self.service_file_json.write('\n')

    #  ----------------------------------------  Tasks ---------------------------------------------
    def parse_task_scheduler(self, event):
        """
        Main function to parse task scheduler type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.task_scheduler_file_csv or self.task_scheduler_file_json:
            if str(event_code) in ["106", "107", "140", "141", "200", "201"]:
                self.parse_task_scheduler_from_xml(event)
            if str(event_code) in ["4698", "4702"]:
                pass

    def parse_task_scheduler_from_xml(self, event):
        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        event_code = event.get("event_identifier")
        name = "-"
        task_name = "-"
        instance_id = "-"
        action_name = "-"
        result_code = "-"
        user_name = "-"
        user_context = "-"

        for data in event_data:
            if data.get("@Name", "") == "Name":
                name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskName":
                task_name = data.get("#text", "-")
            elif data.get("@Name", "") == "InstanceId":
                instance_id = data.get("#text", "-")
            elif data.get("@Name", "") == "ActionName":
                action_name = data.get("#text", "-")
            elif data.get("@Name", "") == "ResultCode":
                result_code = data.get("#text", "-")
            elif data.get("@Name", "") == "UserName":
                user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "UserContext":
                user_context = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                                  ts_time, self.separator,
                                                                  event_code, self.separator,
                                                                  name, self.separator,
                                                                  task_name, self.separator,
                                                                  instance_id, self.separator,
                                                                  action_name, self.separator,
                                                                  result_code, self.separator,
                                                                  user_name, self.separator,
                                                                  user_context)
            self.task_scheduler_file_csv.write(res)
            self.task_scheduler_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "name": name,
                "task_name": task_name,
                "instance_id": instance_id,
                "action_name": action_name,
                "result_code": result_code,
                "user_name": user_name,
                "user_context": user_context,
                "Artefact": "EVTX_TASK_SCHEDULER"
            }

            json.dump(res, self.task_scheduler_file_json)
            self.task_scheduler_file_json.write('\n')

        '''
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {})
        event_code = event.get("event_identifier")

        name = event_data.get("Name", "-")
        task_name = event_data.get("TaskName", "-")
        instance_id = event_data.get("InstanceId", "-")
        action_name = event_data.get("ActionName", "-")
        result_code = event_data.get("ResultCode", "-")
        user_name = event_data.get("UserName", "-")
        user_context = event_data.get("UserContext", "-")

        '''

    #  ----------------------------------------  PowerShell ---------------------------------------------
    def parse_powershell(self, event):
        """
        Main function to parse powershell type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        event_code = event.get("event_identifier")
        if self.powershell_script_file_csv or self.powershell_script_file_json:
            if str(event_code) in ["4104", "4105", "4106"]:
                self.parse_powershell_script_from_xml(event)
        if self.powershell_file_csv or self.powershell_file_json:
            if str(event_code) in ["400", "600"]:
                self.parse_powershell_cmd_from_xml(event)

    def parse_powershell_script_from_xml(self, event):
        """
        Function to parse powershell script execution log type.
        It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        path_to_script = "-"
        script_block_text = "-"

        for data in event_data:
            if data.get("@Name", "") == "Path":
                path_to_script = data.get("#text", "-")

            elif data.get("@Name", "") == "ScriptBlockText":
                script_block_text = str(data.get("#text", "-")).replace("\n", "")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              event_code, self.separator,
                                              path_to_script, self.separator,
                                              script_block_text)
            self.powershell_script_file_csv.write(res)
            self.powershell_script_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "path_to_script": path_to_script,
                "script_block_text": script_block_text,
                "Artefact": "EVTX_POWERSHELL"
            }

            json.dump(res, self.powershell_script_file_json)
            self.powershell_script_file_json.write('\n')

    def parse_powershell_cmd_from_xml(self, event):
        """
        Function to parse powershell cmdu execution log type. It will parse and write results to the appropriate
        result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])
        cmdu = "-"

        for line in event_data:
            if "HostApplication=" in line:
                l2 = line.split("\n")
                for i in l2:
                    if "HostApplication" in i:
                        cmdu = i.split("HostApplication=")[1].replace("\n", " ").replace("\t", "").replace("\r", "")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                          ts_time, self.separator,
                                          event_code, self.separator,
                                          cmdu)
            self.powershell_file_csv.write(res)
            self.powershell_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "cmdu": cmdu,
                "Artefact": "POWERSHELL"
            }

            json.dump(res, self.powershell_file_json)
            self.powershell_file_json.write('\n')

    #  ----------------------------------------  App Experience ---------------------------------------------
    def parse_app_experience(self, event):
        """
        Main function to parse application experience type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.app_exp_file_csv or self.app_exp_file_json:
            if str(event_code) in ["500", "505", "17"]:
                self.parse_app_experience_from_xml(event)

    def parse_app_experience_from_xml(self, event):
        """
        Function to parse application experience log type.
        It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)

        fix_name = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("FixName")
        exe_path = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("ExePath")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              event_code, self.separator,
                                              fix_name, self.separator,
                                              exe_path)
            self.app_exp_file_csv.write(res)
            self.app_exp_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "fix_name": fix_name,
                "exe_path": exe_path,
                "Artefact": "APP_EXPERIENCE"
            }

            json.dump(res, self.app_exp_file_json)
            self.app_exp_file_json.write('\n')

    #  -------------------------------------------------------------  Hives --------------------------------------------

    def parse_hives(self, line):
        """
        Main function to parse windows hive type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        hive_type = self.identify_artefact_by_parser_name(line)
        if hive_type == "amcache":
            if self.amcache_res_file_csv or self.amcache_res_file_json:
                self.parse_amcache(line)
        if hive_type == "appCompat":
            if self.app_compat_res_file_csv or self.app_compat_res_file_json:
                self.parse_app_compat_cache(line)
        if hive_type == "sam":
            if self.sam_res_file_csv or self.sam_res_file_json:
                self.parse_sam(line)
        if hive_type == "userassist":
            if self.user_assist_file_csv or self.user_assist_file_json:
                self.parse_user_assist(line)
        if hive_type == "mru":
            if self.mru_res_file_csv or self.mru_res_file_json:
                self.parse_mru(line)
        if hive_type == "run":
            if self.run_res_file_csv or self.run_res_file_json:
                self.parse_run(line)

    def parse_amcache(self, event):
        """
        Function to parse amcache hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        full_path = event.get("full_path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            identifier = event.get("program_identifier", "-")
            sha256_hash = event.get("sha256_hash", "-")

            if self.output_type in ["csv", "all"]:
                # res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, name, self.separator, identifier)
                res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  name, self.separator,
                                                  full_path, self.separator,
                                                  identifier, self.separator,
                                                  sha256_hash)
                self.amcache_res_file_csv.write(res)
                self.amcache_res_file_csv.write('\n')

            if self.output_type in ["json", "all"]:
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "fullPath": full_path,
                    "identifier": identifier,
                    "hash": sha256_hash,
                    "Artefact": "AMCACHE"
                }
                json.dump(res, self.amcache_res_file_json)
                self.amcache_res_file_json.write('\n')

    def parse_app_compat_cache(self, event):
        """
        Function to parse app compat hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        full_path = event.get("path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            sha256_hash = event.get("sha256_hash", "-")

            if self.output_type in ["csv", "all"]:
                # res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,ts_time, self.separator,name, self.separator,full_path)
                res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  name, self.separator,
                                                  full_path, self.separator,
                                                  sha256_hash)
                self.app_compat_res_file_csv.write(res)
                self.app_compat_res_file_csv.write('\n')

            if self.output_type in ["json", "all"]:
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "identifier": full_path,
                    "hash": sha256_hash,
                    "Artefact": "APP_COMPAT_CACHE"
                }
                json.dump(res, self.app_compat_res_file_json)
                self.app_compat_res_file_json.write('\n')

    def parse_sam(self, event):
        """
        Function to parse sam hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        user_name = event.get("username", "-")
        login_count = event.get("login_count", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                          ts_time, self.separator,
                                          user_name, self.separator,
                                          login_count)
            self.sam_res_file_csv.write(res)
            self.sam_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "user_name": user_name,
                "login_count": login_count,
                "Artefact": "SAM"
            }
            json.dump(res, self.sam_res_file_json)
            self.sam_res_file_json.write('\n')

    def parse_user_assist(self, event):
        """
        Function to user assist artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        value_name = event.get("value_name", "-")
        application_focus_count = event.get("application_focus_count", "-")
        application_focus_duration = event.get("application_focus_duration", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              value_name, self.separator,
                                              application_focus_count, self.separator,
                                              application_focus_duration)
            self.user_assist_file_csv.write(res)
            self.user_assist_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "value_name": value_name,
                "application_focus_count": application_focus_count,
                "application_focus_duration": application_focus_duration,
                "Artefact": "USER_ASSIST"
            }
            json.dump(res, self.user_assist_file_json)
            self.user_assist_file_json.write('\n')

    def parse_mru(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appr)à   opriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            if event.get("parser") == "winreg/bagmru/shell_items":
                shell_item_path = event.get("shell_item_path", "-")
                name = event.get("name", "-")

                if self.output_type in ["csv", "all"]:
                    res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  name, self.separator,
                                                  shell_item_path)
                    self.mru_res_file_csv.write(res)
                    self.mru_res_file_csv.write('\n')

                if self.output_type in ["json", "all"]:
                    res = {
                        "caseName": self.case_name,
                        "workstation_name": self.machine_name,
                        "timestamp": "{}T{}".format(ts_date, ts_time),
                        "name": name,
                        "shell_item_path": shell_item_path,
                        "Artefact": "MRU"
                    }
                    json.dump(res, self.mru_res_file_json)
                    self.mru_res_file_json.write('\n')

            elif event.get("entries"):
                entries = event.get("entries")
                if type(entries) == list:
                    for entrie_item in entries:
                        splited_entrie = entrie_item.split("Index:")
                        for entrie in splited_entrie:
                            header = r'( \d{1,9} \[MRU Value \d{1,9}\]: Shell item path:)|(<UNKNOWN: .*?>)|((\d|[a-z]){1,9} \[MRU Value .{1,9}\]:)'
                            cleaned = re.sub(header, '', entrie).strip()
                            if cleaned:
                                if self.output_type in ["csv", "all"]:
                                    res = "{}{}{}{}-{}{}".format(ts_date, self.separator,
                                                                 ts_time, self.separator,
                                                                 self.separator,
                                                                 cleaned)
                                    self.mru_res_file_csv.write(res)
                                    self.mru_res_file_csv.write('\n')

                                if self.output_type in ["json", "all"]:
                                    res = {
                                        "caseName": self.case_name,
                                        "workstation_name": self.machine_name,
                                        "timestamp": "{}T{}".format(ts_date, ts_time),
                                        "mru_entrie": cleaned,
                                        "Artefact": "MRU"
                                    }
                                    json.dump(res, self.mru_res_file_json)
                                    self.mru_res_file_json.write('\n')
                else:
                    splited_entrie = entries.split("Index:")
                    for entrie in splited_entrie:
                        header = r'( \d{1,9} \[MRU Value \d{1,9}\]: Shell item path:)|(<UNKNOWN: .*?>)|((\d|[a-z]){1,9} \[MRU Value .{1,9}\]:)'
                        cleaned = re.sub(header, '', entrie).strip()
                        if cleaned:
                            if self.output_type in ["csv", "all"]:
                                res = "{}{}{}{}-{}{}".format(ts_date, self.separator,
                                                             ts_time, self.separator,
                                                             self.separator,
                                                             cleaned)
                                self.mru_res_file_csv.write(res)
                                self.mru_res_file_csv.write('\n')

                            if self.output_type in ["json", "all"]:
                                res = {
                                    "caseName": self.case_name,
                                    "workstation_name": self.machine_name,
                                    "timestamp": "{}T{}".format(ts_date, ts_time),
                                    "mru_entrie": cleaned,
                                    "Artefact": "MRU"
                                }
                                json.dump(res, self.mru_res_file_json)
                                self.mru_res_file_json.write('\n')
        except:
            print("Error parsing MRU entries")
            print(traceback.format_exc())

    def parse_run(self, event):
        """
        Function to parse run/RunOnce reg key entries.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        entries = event.get("entries", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if entries:
            for entrie in entries:
                if self.output_type in ["csv", "all"]:
                    res = "{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              entrie)
                    self.run_res_file_csv.write(res)
                    self.run_res_file_csv.write('\n')

                if self.output_type in ["json", "all"]:
                    res = {
                        "caseName": self.case_name,
                        "workstation_name": self.machine_name,
                        "timestamp": "{}T{}".format(ts_date, ts_time),
                        "run_entrie": entrie,
                        "Artefact": "RUN_KEY"
                    }
                    json.dump(res, self.run_res_file_json)
                    self.run_res_file_json.write('\n')

    #  -------------------------------------------------------------  DB -----------------------------------------------

    def parse_db(self, line):
        """
        Main function to parse db type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        db_type = self.identify_artefact_by_parser_name(line)
        if db_type == "ff_history":
            if self.ff_history_res_file_csv or self.ff_history_res_file_json:
                self.parse_ff_history(line)
        if db_type == "ie_history":
            if self.ie_history_res_file_csv or self.ie_history_res_file_json:
                pass
        if db_type == "srum":
            if self.srum_res_file_csv or self.srum_res_file_json:
                self.parse_srum(line)

    def parse_srum(self, event):
        """
        Function to parse srum artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        description = event.get("message", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}".format(ts_date, self.separator,
                                      ts_time, self.separator,
                                      description)
            self.srum_res_file_csv.write(res)
            self.srum_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "description": description,
                "Artefact": "SRUM"
            }
            json.dump(res, self.srum_res_file_json)
            self.srum_res_file_json.write('\n')

    def parse_ff_history(self, event):
        """
        Function to parse firefox history.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        url = event.get("url", "-")
        visit_count = event.get("visit_count", "-")
        visit_type = event.get("visit_type", "-")
        is_typed = event.get("typed", "-")
        from_visit = event.get("from_visit", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                      ts_time, self.separator,
                                                      url, self.separator,
                                                      visit_count, self.separator,
                                                      visit_type, self.separator,
                                                      is_typed, self.separator,
                                                      from_visit)
            self.ff_history_res_file_csv.write(res)
            self.ff_history_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "url": url,
                "visit_count": visit_count,
                "visit_type": visit_type,
                "is_typed": is_typed,
                "from_visit": from_visit,
                "Artefact": "FF_HISTORY"
            }
            json.dump(res, self.ff_history_res_file_json)
            self.ff_history_res_file_json.write('\n')

    #  ------------------------------------------------------  Win Files -----------------------------------------------

    def parse_win_file(self, line):
        """
        Main function to parse windows type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        file_type = self.identify_artefact_by_parser_name(line)
        if file_type == "prefetch":
            if self.prefetch_res_file_csv or self.prefetch_res_file_json:
                self.parse_prefetch(line)
        if file_type == "lnk":
            if self.lnk_res_file_csv or self.lnk_res_file_json:
                self.parse_lnk(line)

    def parse_prefetch(self, event):
        """
        Function to parse prefetch files.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        run_count = event.get("run_count", "-")
        path_hints = event.get("path_hints", "-")
        executable = event.get("executable", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              executable, self.separator,
                                              path_hints, self.separator,
                                              run_count)
            self.prefetch_res_file_csv.write(res)
            self.prefetch_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "executable": executable,
                "path_hints": path_hints,
                "run_count": run_count,
                "Artefact": "PREFETCH"
            }
            json.dump(res, self.prefetch_res_file_json)
            self.prefetch_res_file_json.write('\n')

    def parse_lnk(self, event):
        """
        Function to parse lnk type artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        description = event.get("description", "-")
        working_directory = event.get("working_directory", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if description != "-" and working_directory != "-":
            if self.output_type in ["csv", "all"]:
                res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              description, self.separator,
                                              working_directory)
                self.lnk_res_file_csv.write(res)
                self.lnk_res_file_csv.write('\n')

            if self.output_type in ["json", "all"]:
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "description": description,
                    "working_directory": working_directory,
                    "Artefact": "LNK"
                }
                json.dump(res, self.lnk_res_file_json)
                self.lnk_res_file_json.write('\n')

    #  -------------------------------------------------------------  MFT --------------------------------------------

    def parse_mft(self, line):
        """
        Main function to parse windows mft
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        reg_ntfs = re.compile(r'NTFS')
        if not self.config.get("mft", "") or not line:
            return
        parser = line.get("parser")
        if parser in ["usnjrnl"]:
            self.parse_usnjrl(line)
        elif parser in ["mft"]:
            self.parse_file_mft(line)
        elif parser in ["filestat"] and re.search(reg_ntfs, json.dumps(line)):
            self.parse_filestat(line)

    # TODO: Improve name regex
    def parse_usnjrl(self, event):
        """
        :param event: (dict) dict containing one line of the plaso timeline,
        :return:
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        msg = event.get("message")
        file_name_re = re.compile(r'^(.{1,}\.){1,}(\w){1,3}')
        file_name = re.search(file_name_re, msg)
        update_reason_reg = re.compile(r'Update reason: (.*)')
        update_reason = re.search(update_reason_reg, msg)
        if update_reason:
            try:
                update_reason = update_reason.group(1).replace(',', '')
            except:
                update_reason = "noReason"
        if file_name:
            try:
                file_name = file_name.group()
            except:
                pass

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  "USNJRNL", self.separator,
                                                  "N/A", self.separator,
                                                  update_reason, self.separator,
                                                  file_name)
            self.mft_res_file_csv.write(res)
            self.mft_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "workstation_name": self.machine_name,
                "message": msg,
                "file_name": file_name,
                "Artefact": "NTFS_USN"

            }
            json.dump(res, self.mft_res_file_json)
            self.mft_res_file_json.write('\n')

    def parse_filestat(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        file_name_path = event.get("filename")
        file_type = event.get("file_entry_type")
        action = event.get("timestamp_desc")
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  'FILESTAT', self.separator,
                                                  file_type, self.separator,
                                                  action, self.separator,
                                                  file_name_path)
            self.mft_res_file_csv.write(res)
            self.mft_res_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time, ),
                "workstation_name": self.machine_name,
                "action": action,
                "file_type": file_type,
                "path": file_name_path,
                "Artefact": "NTFS_FILESTAT"
            }
            json.dump(res, self.mft_res_file_json)
            self.mft_res_file_json.write('\n')

    def parse_file_mft(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        file_name_path = event.get("filename")
        file_type = event.get("file_entry_type")
        action = event.get("timestamp_desc")
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  "MFT", self.separator,
                                                  file_type, self.separator,
                                                  action, self.separator,
                                                  file_name_path)
            self.mft_res_file_csv.write(res)
            self.mft_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time, ),
                "workstation_name": self.machine_name,
                "action": action,
                "file_type": file_type,
                "path": file_name_path,
                "Artefact": "NTFS_MFT"
            }
            json.dump(res, self.mft_res_file_json)
            self.mft_res_file_json.write('\n')

    def parse_windows_defender(self, line):
        """
        Main function to parse windows defender logs
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if not self.config.get("windefender", "") or not line:
            return
        event_code = str(line.get("event_identifier"))
        if event_code in ["1116"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                self.parse_windef_detection_from_xml(line)
        if event_code in ["1117", "1118", "1119"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                self.parse_windef_action_from_xml(line)
        if event_code in ["1006"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                pass
                # self.parse_windef_detection_from_xml_legacy(line)
        if event_code in ["1007"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                pass
                # self.parse_windef_action_from_xml_legacy(line)

    def parse_windef_detection_from_xml(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1116 - Detection"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              threat_name, self.separator,
                                                              severity, self.separator,
                                                              detection_user, self.separator,
                                                              process_name, self.separator,
                                                              path, self.separator,
                                                              action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.windefender_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windef_action_from_xml(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        evt_code = str(event.get("event_identifier"))
        event_code = "{} - Action".format(evt_code)
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.windefender_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windef_detection_from_xml_legacy(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1006"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.logon_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windef_action_from_xml_legacy(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1117"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.windefender_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windows_startup_shutdown(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if event_code == 4608:
            msg = "WINDOWS STARTUP"
        elif event_code == 4609:
            msg = "WINDOWS SHUTDOWN"
        else:
            msg = "-"
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, msg)
            self.windows_start_stop_res_file_csv.write(res)
            self.windows_start_stop_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "action": msg,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.windows_start_stop_res_file_json)
            self.windows_start_stop_res_file_json.write('\n')

    def list_files_recursive(self, folder_path, glob_pattern):
        l_file = []
        path_folder = pathlib.Path(folder_path)
        for item in path_folder.rglob(glob_pattern):
            if item.is_file():
                l_file.append(item)
        return l_file

    def clean_duplicates(self, dir_to_clean):

        """
        To clean duplicates line in file
        :return:
        """
        try:
            l_file = self.list_files_recursive(dir_to_clean, "*")
            for file in l_file:
                self.clean_duplicate_in_file(file)
        except:
            print(traceback.format_exc())

    def clean_duplicate_in_file(self, file):

        seen_lines = set()
        l_temp = []

        with open(file, 'r') as f:
            for line in f:
                if line not in seen_lines:
                    seen_lines.add(line)
                    l_temp.append(line)

        with open(file, 'w') as f:
            f.writelines(l_temp)

    def create_timeline(self):
        timeline = []
        for file in self.list_files_recursive(self.work_dir, "*.csv"):
            try:
                with open(file) as f:
                    next(f)
                    for line in f:
                        f_line = self.format_line(line, file.stem)
                        if f_line:
                            timeline.append(f_line)
            except StopIteration:
                print("stop iteration in file {}, skipping".format(str(file)))
            except:
                print(traceback.format_exc())

        self.timeline_file_csv = self.initialise_result_file_csv(self.l_csv_header_timeline, "timeline")
        sorted_timeline = sorted(timeline)
        for entry in sorted_timeline:
            self.timeline_file_csv.write(entry)
        self.timeline_file_csv.close()

    def format_line(self, line, source):
        try:
            l_line = line.split("|")
            l_line.insert(2, source)
            return "|".join(l_line)
        except:
            print(traceback.format_exc())

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse a json plaso timeline'))

    argument_parser.add_argument('-t', '--timeline', action="store",
                                 required=True, dest="timeline", default=False,
                                 help="path to the timeline , must be json timeline")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    argument_parser.add_argument("-c", "--casename", action="store",
                                 required=False, dest="case_name", default=None,
                                 help="name of the case u working on")

    argument_parser.add_argument("-s", "--separator", action="store",
                                 required=False, dest="separator", default="|",
                                 help="separator that will be used on csv files")

    argument_parser.add_argument("--type", action="store",
                                 required=False, dest="type_output", default="csv",
                                 choices=["csv", "json", "all"], metavar="csv or json or all for both",
                                 help="type of the output file format : csv or json or both. Default is csv")

    argument_parser.add_argument("-m", "--machine_name", action="store",
                                 required=False, dest="machine_name", default="machineX",
                                 metavar="name of the machine",
                                 help="name of the machine")

    argument_parser.add_argument("--config", action="store",
                                 required=False, dest="config_file", default=None,
                                 help="path to the json config file to be used")

    return argument_parser


def validate_json(timeline):
    with open(timeline, 'r') as tl:
        first_line = tl.readline()
        try:
            json.loads(first_line)
            return True
        except ValueError as err:
            return False


# File appears not to be in CSV format; move along
def check_input(timeline):
    if validate_json(timeline):
        return "json"
    else:
        print("Cannot read timeline correctly, are you sure that it is a valid json line format?")
        exit(1)


if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    start_time = time.time()
    now = datetime.now()  # current date and time
    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

    print("Started at:", date_time)

    type_input = check_input(args.timeline)
    if type_input == "json":
        mp = MaximumPlasoParserJson(args.output_dir, args.type_output, args.separator, args.case_name, args.config_file,
                                    args.machine_name)
        mp.parse_timeline(args.timeline)
    else:
        print("Timeline is not a valide Json, aboarding")
        exit(1)

    print("Finished in {} secondes".format(time.time() - start_time))

"""
location": "Microsoft-Windows-Windows Defender%4Operational.evtx
location": "Microsoft-Windows-Windows Defender%4WHC.evtx
event id 1116 1117 1015 1013 1014 1012 1011 1010 1009 1008 1007 1006 1005 1004 1003 1002 

location": "Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx
location": "Microsoft-Windows-Windows Firewall With Advanced Security%4FirewallDiagnostics.evtx
location": "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx
location": "Microsoft-Windows-WindowsUpdateClient%4Operational.evtx
location": "Microsoft-Windows-WinINet-Config%4ProxyConfigChanged.evtx
location": "Microsoft-Windows-Winlogon%4Operational.evtx
location": "Microsoft-Windows-WinRM%4Operational.evtx
location": "Microsoft-Windows-WMI-Activity%4Operational.evtx

4608	Windows is starting up.
This event is generated when a Windows machine is started. It is logged on domain controllers and member computers. 
 	4609	Windows is shutting down.
This event is generated when a Windows machine is shutting down. It is logged on domain controllers and member computers.  
 	1102	The audit log was cleared.
This event is generated whenever the security log is cleared. It is logged on domain controllers and member computers.  
 	4614	A notification package has been loaded by the Security Account Manager.
This event is generated when a user attempts to change their password. It is logged on domain controllers and member computers. 


Send to ELK
jq -c -r '. | {"index": {"_index": "geelong"}}, .' amcache.json | curl -XPOST "http://localhost:9200/_bulk?pretty" -H "Content-Type: application/json" --data-binary @-

"""
