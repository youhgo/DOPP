#!/usr/bin/python3
import json
import os
import argparse
from pathlib import Path
import re


class EventParser:
    """
       Class to parse event json files to human-readable format |DATE|TIME|ETC|ETC
       Attributes :
    """

    def __init__(self, events_json_directory, output_directory) -> None:
        """
        The constructor for EventParser class.
        Parameters:
        """
        self.separator = "|"
        self.work_dir = events_json_directory
        self.output_directory = output_directory

        self.l_csv_header_4624 = ["Date", "Time", "event_code", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port", "logon_type"]
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
        self.l_csv_header_windefender = ["Date", "Time", "Event", "ThreatName", "Severity", "User", "ProcessName",
                                         "Path", "Action"]
        self.l_csv_header_start_stop = ["Date", "Time", "message"]

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

        self.windefender_res_file_csv = ""

        self.windows_start_stop_res_file_csv = ""

        self.initialise_results_files_csv()

    def initialise_result_file_csv(self, header, file_name, extension="csv"):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param header: (list[str]) list containing all column name
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.output_directory, "{}.{}".format(file_name, extension)), 'a')
        result_file_stream.write(self.separator.join(header))
        result_file_stream.write("\n")
        return result_file_stream

    def initialise_results_files_csv(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

        self.logon_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_4624, "user_logon_id4624")
        self.logon_failed_file_csv = self.initialise_result_file_csv(self.l_csv_header_4625,
                                                                     "user_failed_logon_id4625")
        self.logon_spe_file_csv = self.initialise_result_file_csv(self.l_csv_header_4672,
                                                                  "user_special_logon_id4672")
        self.logon_exp_file_csv = self.initialise_result_file_csv(self.l_csv_header_4648,
                                                                  "user_explicit_logon_id4648")
        self.new_proc_file_csv = self.initialise_result_file_csv(self.l_csv_header_4688,
                                                                 "new_proc_file_id4688")
        self.windows_start_stop_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_start_stop,
                                                                               "windows_start_stop")
        self.task_scheduler_file_csv = self.initialise_result_file_csv(self.l_csv_header_tscheduler,
                                                                       "task_scheduler")
        self.remote_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_remot_rdp,
                                                                   "remote_rdp")
        self.local_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_local_rdp,
                                                                  "local_rdp")
        self.bits_file_csv = self.initialise_result_file_csv(self.l_csv_header_bits, "bits")
        self.service_file_csv = self.initialise_result_file_csv(self.l_csv_header_7045, "new_service_id7045")
        self.powershell_file_csv = self.initialise_result_file_csv(self.l_csv_header_powershell,
                                                                   "powershell")
        self.powershell_script_file_csv = self.initialise_result_file_csv(self.l_csv_header_script_powershell,
                                                                          "powershell_script")
        self.wmi_file_csv = self.initialise_result_file_csv(self.l_csv_header_wmi, "wmi")
        self.windefender_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_windefender,
                                                                        "windefender")

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

    def format_system_time(self, evt_timestamp):
        try:
            if evt_timestamp == "-":
                return
            l_time = evt_timestamp.split("T")
            if l_time:
                ts_date = l_time[0]
                ts_time = l_time[1].split(".")[0]
                return ts_date, ts_time
        except:
            return evt_timestamp, "-"

    def parse_logon(self, event):
        """
        Parse 4624 event ID
        :param event: dict
        :return:
        """
        event_code = "4624"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

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

    def parse_failed_logon(self, event):
        """
        parse 4625 event id
        :param event: dict
        :return:
        """
        event_code = "4625"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

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

    def parse_spe_logon(self, event):
        """
        Parse 4672 event id
        :param event: dict
        :return:
        """
        event_code = "4672"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

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

    def parse_exp_logon(self, event):
        """
        Parse 4648 event id
        :param event: dict
        :return:
        """
        event_code = "4648"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

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

    def parse_new_proc(self, event):
        """
        Parse 4688 event ID
        :param event: dict
        :return:
        """
        event_code = "4688"
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        parent_proc_name = event.get("Event", {}).get("EventData", {}).get("ParentProcessName", "-")
        new_proc_name = event.get("Event", {}).get("EventData", {}).get("NewProcessName", "-")
        cmd_line = event.get("Event", {}).get("EventData", {}).get("CommandLine", "-")

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

    def parse_security_evtx(self, file_path):
        """
        Main function to parse evtx security json files
        :param event: str: path to json converted security evtx file
        :return:
        """

        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["4624"]:
                    self.parse_logon(ev)
                if event_code in ["4625"]:
                    self.parse_failed_logon(ev)

                if event_code in ["4672"]:
                    self.parse_spe_logon(ev)

                if event_code in ["4648"]:
                    self.parse_exp_logon(ev)

                if event_code in ["4688"]:
                    self.parse_new_proc(ev)

    def parse_task_scheduler_new(self, event):
        """
        Parse task scheduler event ID for newer logs of windows
        :param event: dict
        :return:
        """

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        name = event.get("Event", {}).get("EventData", {}).get("Name", "-")
        task_name = event.get("Event", {}).get("EventData", {}).get("TaskName", "-")
        instance_id = event.get("Event", {}).get("EventData", {}).get("InstanceId", "-")
        action_name = event.get("Event", {}).get("EventData", {}).get("ActionName", "-")
        result_code = event.get("Event", {}).get("EventData", {}).get("ResultCode", "-")
        user_name = event.get("Event", {}).get("EventData", {}).get("UserName", "-")
        user_context = event.get("Event", {}).get("EventData", {}).get("UserContext", "-")

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

    def parse_task_scheduler(self, file_path):
        """
       Main function to parse evtx task scheduler json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as scheduled_file:
            for event in scheduled_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["106", "107", "140", "141", "200", "201"]:
                    self.parse_task_scheduler_new(ev)

    def parse_rdp_remote_connexion(self, event):
        """
        Parse task rdp remote connexion event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        user_name = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Param1", "-")
        ip_addr = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Param3", "-")

        res = "{}{}{}{}{}{}InitConnexion{}{}{}{}".format(ts_date, self.separator,
                                                         ts_time, self.separator,
                                                         event_code, self.separator,
                                                         self.separator,
                                                         user_name, self.separator,
                                                         ip_addr)
        self.remote_rdp_file_csv.write(res)
        self.remote_rdp_file_csv.write('\n')

    def parse_rdp_remote_evtx(self, file_path):
        """
       Main function to parse evtx rdp remote json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["1149"]:
                    self.parse_rdp_remote_connexion

    def parse_rdp_local_connexion(self, event):
        """
        Parse task rdp local connexion event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        user_name = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("User", "-")
        ip_addr = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Adress", "-")
        session_id = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("SessionID", "-")
        source = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Source", "-")
        target_session = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("TargetSession", "-")
        reason_n = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Reason", "-")
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")

        reason = "-"
        if event_code == "21":
            reason = "AuthSuccess"
        if event_code == "24":
            reason = "UserDisconnected"
        if event_code == "25":
            reason = "UserReconnected"
        if event_code == "39":
            reason = "UserHasBeenDisconnected"
        if event_code == "40":
            reason = "UserHasBeenDisconnected"

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

    def parse_rdp_local_evtx(self, file_path):
        """
       Main function to parse rdp local json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["21", "24", "25", "39", "40"]:
                    self.parse_rdp_local_connexion(ev)

    def parse_bits(self, file_path):
        """
       Main function to parse evtx bits json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["3", "4", "59", "60", "61"]:
                    self.parse_bits_evtx(ev)

    def parse_bits_evtx(self, event):
        """
        Parse bits event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        identifiant = event.get("Event", {}).get("EventData", {}).get("Id", "-")
        job_id = event.get("Event", {}).get("EventData", {}).get("jobId", "-")
        job_title = event.get("Event", {}).get("EventData", {}).get("jobTitle", "-")
        job_owner = event.get("Event", {}).get("EventData", {}).get("jobOwner", "-")
        user = event.get("Event", {}).get("EventData", {}).get("User", "-")
        bytes_total = event.get("Event", {}).get("EventData", {}).get("bytesTotal", "-")
        bytes_transferred = event.get("Event", {}).get("EventData", {}).get("bytesTransferred", "-")
        file_count = event.get("Event", {}).get("EventData", {}).get("fileCount", "-")
        file_length = event.get("Event", {}).get("EventData", {}).get("fileLength", "-")
        file_time = event.get("Event", {}).get("EventData", {}).get("fileTime", "-")
        name = event.get("Event", {}).get("EventData", {}).get("name", "-")
        url = event.get("Event", {}).get("EventData", {}).get("url", "-")
        process_path = event.get("Event", {}).get("EventData", {}).get("processPath", "-")

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

    def parse_system_evtx(self, file_path):
        """
        Main function to parse system type logs
        :param file_path: (str) path to the evtx json file,
        :return: None
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                try:
                    event_code = ev.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
                except:
                    event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["7034", "7045"]:
                    self.parse_service_evtx(ev)

    def parse_service_evtx(self, event):
        """
        Parse services (7045) event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
        account_name = event.get("Event", {}).get("EventData", {}).get("AccountName", "-")
        img_path = event.get("Event", {}).get("EventData", {}).get("ImagePath", "-")
        service_name = event.get("Event", {}).get("EventData", {}).get("ServiceName", "-")
        start_type = event.get("Event", {}).get("EventData", {}).get("StartType", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              event_code, self.separator,
                                              account_name, self.separator,
                                              img_path, self.separator,
                                              service_name, self.separator,
                                              start_type)

        self.service_file_csv.write(res)
        self.service_file_csv.write('\n')

    def parse_powershell_script(self, event):
        """
        Parse powershell script event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        path_to_script = event.get("Event", {}).get("EventData", {}).get("Path", "-")
        script_block_text = event.get("Event", {}).get("EventData", {}).get("ScriptBlockText", "-")

        res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                          ts_time, self.separator,
                                          event_code, self.separator,
                                          path_to_script, self.separator,
                                          script_block_text)
        self.powershell_script_file_csv.write(res)
        self.powershell_script_file_csv.write('\n')

    def parse_powershell_cmd(self, event):
        """
        Parse powershell cmd event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
        cmdu = "-"

        evt_data = event.get("Event", {}).get("EventData", {}).get("Data", "-")
        for line in evt_data:
            if "HostApplication=" in line:
                l2 = line.split("\n")
                for i in l2:
                    if "HostApplication" in i:
                        cmdu = i.split("HostApplication=")[1].replace("\n", " ").replace("\t", "").replace("\r", "")

        res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                      ts_time, self.separator,
                                      event_code, self.separator,
                                      cmdu)

        self.powershell_file_csv.write(res)
        self.powershell_file_csv.write('\n')

    def parse_powershell_operationnal(self, file_path):
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["4104"]:
                    self.parse_powershell_script(ev)

    def parse_windows_powershell(self, file_path):
        """
       Main function to parse evtx powershell json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
                if event_code in ["400", "600"]:
                    self.parse_powershell_cmd(ev)

    def parse_wmi_evtx(self, event):
        """
        Function to parse wmi log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")

        operation_name = list(event.get("Event", {}).get("UserData", {}).keys())[0]
        op_dict = event.get("Event", {}).get("UserData", {}).get(operation_name, {})

        user = op_dict.get("User", "-")
        namespace = op_dict.get("NamespaceName", "-")
        consumer = op_dict.get("CONSUMER", "-")
        cause = op_dict.get("PossibleCause", "-")
        query = op_dict.get("Query", "-")

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

    def parse_wmi_failure_evtx(self, event):
        """
        Function to parse wmi failure log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the evtx json file,
        :return: None
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")

        operation_name = list(event.get("Event", {}).get("UserData", {}).keys())[0]
        op_dict = event.get("Event", {}).get("UserData", {}).get(operation_name, {})

        user = op_dict.get("User", "-")
        namespace = op_dict.get("NamespaceName", "-")
        consumer = op_dict.get("CONSUMER", "-")
        cause = op_dict.get("PossibleCause", "-")
        query = op_dict.get("Query", "-")

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

    def parse_wmi(self, file_path):
        """
        Main function to parse wmi type logs
        :param file_path: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if str(event_code) in ["5860", "5861"]:
                    self.parse_wmi_evtx(ev)
                if str(event_code) in ["5858"]:
                    self.parse_wmi_failure_evtx(ev)

    def parse_windows_defender(self, file_path):
        """
        Main function to parse windows defender logs
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["1116"]:
                    self.parse_windef_detection_from_xml(ev)
                if event_code in ["1117", "1118", "1119"]:
                    self.parse_windef_action_from_xml(ev)
                if event_code in ["1006", "1007"]:
                    pass # lacking data to parse

    def parse_windef_detection_from_xml(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1116 - Detection"
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)

        threat_name = event.get("Event", {}).get("EventData", {}).get("Threat Name", "-")
        severity = event.get("Event", {}).get("EventData", {}).get("Severity Name", "-")
        process_name = event.get("Event", {}).get("EventData", {}).get("Process Name", "-")
        detection_user = event.get("Event", {}).get("EventData", {}).get("Detection User", "-")
        path = event.get("Event", {}).get("EventData", {}).get("Path", "-")
        action = event.get("Event", {}).get("EventData", {}).get("Action Name", "-")

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

    def parse_windef_action_from_xml(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        evt_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        event_code = "{} - Action".format(evt_code)
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)

        threat_name = event.get("Event", {}).get("EventData", {}).get("Threat Name", "-")
        severity = event.get("Event", {}).get("EventData", {}).get("Severity Name", "-")
        process_name = event.get("Event", {}).get("EventData", {}).get("Process Name", "-")
        detection_user = event.get("Event", {}).get("EventData", {}).get("Detection User", "-")
        path = event.get("Event", {}).get("EventData", {}).get("Path", "-")
        action = event.get("Event", {}).get("EventData", {}).get("Action Name", "-")

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

    def parse_smb_client_evtx(self, file_path):
        pass # lack of data to create parser

    def parse_smb_server_evtx(self, file_path):
        pass # lack of data to create parser

    def parse_firewall_evtx(self, file_path):
        pass # lack of data to create parser

    def parse_application_evtx(self, file_path):
        pass # lack of data to create parser

    def parse_all(self):
        """
        Main function to parse all  evtx jsonfiles
        """
        search_security = [f for f in os.listdir(self.work_dir) if re.search(r'_Security\.json$', f)]
        search_security2 = [f for f in os.listdir(self.work_dir) if re.search(r'^Security\.json$', f)]
        search_all_security = search_security + search_security2
        if search_all_security:
            relative_file_path = Path(os.path.join(self.work_dir, search_all_security[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_security_evtx(absolute_file_path)

        search_task_scheduler = [f for f in os.listdir(self.work_dir) if
                  re.search(r'Microsoft-Windows-TaskScheduler%4Operational\.json$', f)]
        if search_task_scheduler:
            relative_file_path = Path(os.path.join(self.work_dir, search_task_scheduler[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_task_scheduler(absolute_file_path)

        search_remot_rdp = [f for f in os.listdir(self.work_dir) if
                  re.search(r'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational\.json$', f)]
        if search_remot_rdp:
            relative_file_path_remot = Path(os.path.join(self.work_dir, search_remot_rdp[0]))
            absolute_file_path_remot = relative_file_path_remot.absolute()  # absolute is a Path object
            self.parse_rdp_remote_evtx(absolute_file_path_remot)

        search_local_rdp = [f for f in os.listdir(self.work_dir) if
                  re.search(r'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational\.json$', f)]
        if search_local_rdp:
            relative_file_path_local = Path(os.path.join(self.work_dir, search_local_rdp[0]))
            absolute_file_path_local = relative_file_path_local.absolute()  # absolute is a Path object
            self.parse_rdp_local_evtx(absolute_file_path_local)

        search_bits = [f for f in os.listdir(self.work_dir) if
                       re.search(r'Microsoft-Windows-Bits-Client%4Operational\.json$', f)]
        if search_bits:
            relative_file_path = Path(os.path.join(self.work_dir, search_bits[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_bits(absolute_file_path)

        search_powershell_operational = [f for f in os.listdir(self.work_dir) if
                  re.search(r'Microsoft-Windows-PowerShell%4Operational\.json$', f)]
        if search_powershell_operational:
            relative_file_path = Path(os.path.join(self.work_dir, search_powershell_operational[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_powershell_operationnal(absolute_file_path)

        search_windows_powershell = [f for f in os.listdir(self.work_dir) if
                  re.search(r'Microsoft-Windows-PowerShell\.json$', f)]
        if search_windows_powershell:
            relative_file_path = Path(os.path.join(self.work_dir, search_windows_powershell[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_powershell_cmd(absolute_file_path)

        search_wmi = [f for f in os.listdir(self.work_dir) if
                  re.search(r'Microsoft-Windows-WMI-Activity%4Operational\.json$', f)]
        if search_wmi:
            relative_file_path = Path(os.path.join(self.work_dir, search_wmi[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_wmi(absolute_file_path)

        search_system = [f for f in os.listdir(self.work_dir) if
                  re.search(r'System\.json$', f)]
        if search_system:
            relative_file_path = Path(os.path.join(self.work_dir, search_system[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_system_evtx(absolute_file_path)


def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Parser for json formated evtx'))

    argument_parser.add_argument('-i', '--input', action="store",
                                 required=True, dest="input_dir", default=False,
                                 help="path to the input directory")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    return argument_parser


if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    evtparser = EventParser(args.input_dir, args.output_dir)
    evtparser.parse_all()




