#!/usr/bin/python3
import os
import re
import traceback
import argparse
from pathlib import Path
import xmltodict


class ProcessParser:
    """
    Class to parsed various tool results files into straight forward human readble csv.
    (sysinternals Autoruns, DFIR-ORC PROCESS1, DFIR-ORC PROCESS2, DFIR-ORC PROCESS INFO, DFIR-ORC PROCESS_TIMELINE
    DFIR-ORC PROCESS_AUTORUNS)

    """

    def __init__(self, output_directory, artefact_config="", separator="|") -> None:
        """
        The constructor for ProcessParser class.
        :param output_directory: str Full path to the directory where the files will be written
        """
        self.separator = separator
        self.dir_out = output_directory

        if not artefact_config:
            self.artefact_config = {
                "process1": "process1.csv",
                "process2": "process2.csv",
                "autoruns": "autoruns.csv",
                "sample_autoruns": "GetSamples_autoruns.xml",
                "sample_timeline": "GetSamples_timeline.csv",
                "sample_info": "GetSamples_sampleinfo.csv"
                }
        else:
            self.artefact_config = artefact_config


        self.autorun_header_sysinternals = ["Time", "Entry", "Image Path", "Launch String", "MD5"]
        self.process1_header = ["ProcessName", "CommandLine", "CreationDate", "InstallDate", "ExecutablePath",
                                "ExecutionState", "ProcessId", "ParentProcessId"]
        self.process2_header = ["ProcessName", "ProcessPath", "ProcessId"]
        self.process_timeline_header = ["Date", "Time", "Action_type", "ParentProcessId", "ProcessId", "FullPath"]
        self.process_info_header = ["Date", "Time", "Action_type", "ParentProcessId", "ProcessId", "FullPath"]
        self.process_autoruns_header = ["Date", "Time", "Action_type", "ParentProcessId", "ProcessId", "FullPath"]

    def recursive_file_search(self, dir, reg_ex):
        files = []
        for element in os.listdir(dir):
            full_path = os.path.join(dir, element)
            if os.path.isfile(full_path):
                if re.search(reg_ex, element):  # ,  re.IGNORECASE):
                    if full_path not in files:
                        files.append(full_path)
            elif os.path.isdir(full_path):
                files.extend(self.recursive_file_search(full_path, reg_ex))
        return files

    def initialise_result_file_csv(self, header, file_name, extension="csv"):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param header: (list[str]) list containing all column name
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.dir_out, "{}.{}".format(file_name, extension)), 'a')
        result_file_stream.write(self.separator.join(header))
        result_file_stream.write("\n")
        return result_file_stream

    def format_list_user_friendly(self, list_to_format):
        """
        Format a list with | delimiter and sort by date
        :param list_to_format: (list) : a list to be sorted
        :return:
        """
        list_sorted = []
        lines = sorted(list_to_format, key=lambda line: line.split("|")[0])
        for line_sorted in lines:
            splited_line = line_sorted.split("|")
            splited_line[0] = splited_line[0].replace("~", "|").split(".")[0]
            list_sorted.append("|".join(splited_line))
        return list_sorted

    def parse_autoruns_sysinternals(self, file_path):
        """
        Parse the output of SysInternals autorun to a straight forward human readable csv file
        :param file_path: path of the Sysinternals output file
        :return:
        """
        self.autorun_sysinternals_result_file = self.initialise_result_file_csv(self.autorun_header_sysinternals,
                                                                                "autorun_sysinternals_parsed")
        l_res = []
        reg = re.compile(r'^\d{1,10}\-?')

        with open(file_path, "r", encoding="utf-16") as autoruns:
            for lline in autoruns.readlines():
                line = lline.split(',')
                if line:
                    if re.match(reg, line[0]):
                        try:
                            line[0] = line[0].replace("-", "~")  # time
                            line[0] = line[0][:4] + '-' + line[0][4:]  # Entry
                            line[0] = line[0][:7] + '-' + line[0][7:]
                            line[0] = line[0][:13] + ':' + line[0][13:]
                            line[0] = line[0][:16] + ':' + line[0][16:]

                            entry = "-"
                            img_path = "-"
                            launch_str = "-"
                            md5 = "-"
                            if line[2]:
                                entry = line[2]
                            if line[9]:
                                img_path = line[9]
                            if line[11]:
                                launch_str = line[11]
                            if line[12]:
                                md5 = line[12]

                            outLine = "{}{}{}{}{}{}{}{}{}".format(line[0],
                                                                  self.separator, entry,
                                                                  self.separator, img_path,
                                                                  self.separator, launch_str,
                                                                  self.separator, md5)
                            l_res.append(outLine)
                        except Exception as ex:
                            pass

        formated_list = self.format_list_user_friendly(l_res)
        try:
            for line in formated_list:
                self.autorun_sysinternals_result_file.write(line)
                self.autorun_sysinternals_result_file.write("\n")
        except Exception:
            print(traceback.format_exc())

    def parse_process1(self, file_path):
        """
        Parse the output of DFIR-ORC process1 cmd  to a straight forward human readable csv file
        :param file_path: path of the process1 result file
        :return:
        """
        self.process1_result_file = self.initialise_result_file_csv(self.process1_header, "process1_parsed")
        res = "-"
        with open(file_path, "r") as process:
            for lline in process.readlines()[1:]:  # skip header
                line = lline.split(',')
                if line:
                    process_name = "-"
                    command_line = "-"
                    creation_date = "-"
                    install_date = "-"
                    exe_path = "-"
                    exe_state = "-"
                    proc_id = "-"
                    parent_proc_id = "-"

                    if line[1]:
                        process_name = line[1].replace('"', "")
                    if line[17]:
                        command_line = line[17].replace('"', "")
                    if line[19]:
                        creation_date = line[19].replace('"', "")
                    if line[27]:
                        install_date = line[27].replace('"', "")
                    if line[23]:
                        exe_path = line[23].replace('"', "")
                    if line[24]:
                        exe_state = line[24].replace('"', "")
                    if line[44]:
                        proc_id = line[44].replace('"', "")
                    if line[38]:
                        parent_proc_id = line[38].replace('"', "")
                    res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(process_name,
                                                                  self.separator, command_line,
                                                                  self.separator, creation_date,
                                                                  self.separator, install_date,
                                                                  self.separator, exe_path,
                                                                  self.separator, exe_state,
                                                                  self.separator, proc_id,
                                                                  self.separator, parent_proc_id)
                    self.process1_result_file.write(res)
                    self.process1_result_file.write("\n")

    def parse_process2(self, file_path):
        """
        Parse the output of DFIR-ORC process2 cmd  to a straight forward human readable csv file
        :param file_path: path of the process2 result file
        :return:
        """
        self.process2_result_file = self.initialise_result_file_csv(self.process2_header, "process2_parsed")
        res = "-"
        with open(file_path, "r") as process:
            for lline in process.readlines()[1:]:  # skip header
                line = lline.split(',')
                if line:
                    process_name = "-"
                    proc_path = "-"
                    proc_id = "-"
                    if line[0]:
                        process_name = line[0].replace('"', "")
                    if line[7]:
                        proc_path = line[7].replace('"', "")
                    if line[22]:
                        proc_id = line[22].replace('"', "")

                    res = "{}{}{}{}{}".format(process_name, self.separator, proc_path, self.separator, proc_id)

                    self.process2_result_file.write(res)
                    self.process2_result_file.write("\n")

    def parse_process_timeline(self, file_path):
        """
        Parse the output of DFIR-ORC GetSample_timeline  to a straight forward human readable csv file
        :param file_path: path of the GetSample_timeline result file
        :return:
        """
        res = "-"
        self.process_timeline_result_file = self.initialise_result_file_csv(self.process_timeline_header,
                                                                            "process_timeline_parsed")
        with open(file_path, "r") as process_timeline:
            for lline in process_timeline.readlines()[1:]:  # skip header
                line = lline.split(',')
                if line:
                    date = "-"
                    time = "-"
                    type_action = "-"
                    parent_id = "-"
                    proc_id = "-"
                    full_path = "-"

                    if line[1]:
                        date, time, = line[1].replace('"', "").split(" ")
                    if line[2]:
                        type_action = line[2].replace('"', "").replace("\n", "")
                    if line[3]:
                        parent_id = line[3].replace('"', "").replace("\n", "")
                    if line[4]:
                        proc_id = line[4].replace('"', "").replace("\n", "")
                    if line[5]:
                        full_path = line[5].replace('"', "").replace("\n", "")

                    res = "{}{}{}{}{}{}{}{}{}{}{}".format(date,
                                                          self.separator, time,
                                                          self.separator, type_action,
                                                          self.separator, parent_id,
                                                          self.separator, proc_id,
                                                          self.separator, full_path)

                    self.process_timeline_result_file.write(res)
                    self.process_timeline_result_file.write("\n")

    def parse_process_infos(self, file_path):
        """
        Parse the output of DFIR-ORC GetSample_info  to a straight forward human readable csv file
        :param file_path: path of the GetSample__info result file
        :return:
        """

        # ComputerName,FullPath,FileName,Authenticode,Loaded,Registry,Running
        self.process_info_result_file = self.initialise_result_file_csv(self.process_info_header,
                                                                        "process_info_parsed")
        res = "-"
        with open(file_path, "r") as process_timeline:
            for lline in process_timeline.readlines()[1:]:  # skip header
                line = lline.split(',')
                if line:
                    file_name = "-"
                    running = "-"
                    registry = "-"
                    authenticode = "-"
                    loaded = "-"
                    full_path = "-"
                    if line[1]:
                        full_path = line[1].replace('"', "").replace("\n", "")
                    if line[2]:
                        file_name = line[2].replace('"', "").replace("\n", "")
                    if line[3]:
                        authenticode = line[3].replace('"', "").replace("\n", "")
                    if line[4]:
                        loaded = line[4].replace('"', "").replace("\n", "")
                    if line[5]:
                        registry = line[5].replace('"', "").replace("\n", "")
                    if line[6]:
                        running = line[6].replace('"', "").replace("\n", "")

                    res = "{}{}{}{}{}{}{}{}{}{}{}".format(file_name,
                                                          self.separator, running,
                                                          self.separator, registry,
                                                          self.separator, authenticode,
                                                          self.separator, loaded,
                                                          self.separator, full_path)

                    self.process_info_result_file.write(res)
                    self.process_info_result_file.write("\n")

    def parse_process_autoruns(self, file_path):
        """
        Parse the output of DFIR-ORC GetSample_autoruns  to a straight forward human readable csv file
        :param file_path: path of the GetSample_autoruns result file
        :return:
        """

        self.process_autoruns_result_file = self.initialise_result_file_csv(self.process_autoruns_header,
                                                                            "process_autoruns_parsed")
        l_res = []
        res = "-"
        with open(file_path, 'r') as autorun_file:
            file_as_json = xmltodict.parse(autorun_file.read())
            for key, values in file_as_json.items():
                for key1, values1 in values.items():  # value 1 is list
                    for item in values1:
                        date_time = item.get("time", "-")
                        name = item.get("itemname", "-")
                        launchstr = item.get("launchstring", "-")
                        enabled = item.get("enabled", "-")
                        path = item.get("imagepath", "-")

                        date_time = date_time.replace("-", "~")  # time
                        date_time = date_time[:4] + '-' + date_time[4:]  # Entry
                        date_time = date_time[:7] + '-' + date_time[7:]
                        date_time = date_time[:13] + ':' + date_time[13:]
                        date_time = date_time[:16] + ':' + date_time[16:]
                        date, time = date_time.split("~")

                        res = "{}{}{}{}{}{}{}{}{}{}{}".format(date,
                                                              self.separator, time,
                                                              self.separator, name,
                                                              self.separator, launchstr,
                                                              self.separator, enabled,
                                                              self.separator, path)
                        l_res.append(res)
        formated_list = self.format_list_user_friendly(l_res)
        try:
            for line in formated_list:
                self.process_autoruns_result_file.write(line)
                self.process_autoruns_result_file.write("\n")
        except Exception:
            print(traceback.format_exc())

    def parse_all(self, input_dir):
        autoruns_sysinternals_files = self.recursive_file_search(input_dir, self.artefact_config.get("autoruns", ""))
        if autoruns_sysinternals_files:
            for autorun_file in autoruns_sysinternals_files:
                self.parse_autoruns_sysinternals(autorun_file)

        process1_files = self.recursive_file_search(input_dir, self.artefact_config.get("process1", ""))
        if process1_files:
            for process1_file in process1_files:
                self.parse_process1(process1_file)

        process2_files = self.recursive_file_search(input_dir, self.artefact_config.get("process2", ""))
        if process2_files:
            for process2_file in process2_files:
                self.parse_process2(process2_file)

        process_autoruns_files = self.recursive_file_search(input_dir, self.artefact_config.get("sample_autoruns", ""))
        if process_autoruns_files:
            for process_autoruns_file in process_autoruns_files:
                self.parse_process_autoruns(process_autoruns_file)

        process_timeline_files = self.recursive_file_search(input_dir, self.artefact_config.get("sample_timeline", ""))
        if process_timeline_files:
            for process_timeline_file in process_timeline_files:
                self.parse_process_timeline(process_timeline_file)

        process_info_files = self.recursive_file_search(input_dir, self.artefact_config.get("sample_info", ""))
        if process_info_files:
            for process_info_file in process_info_files:
                self.parse_process_infos(process_info_file)



def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Parser for process artefacts collected by DFIR ORC'))

    argument_parser.add_argument('-a', '--all', action="store",
                                 required=False, dest="input_dir", default=False,
                                 help="path to the input dir")

    argument_parser.add_argument('-o', '--output', action="store",
                                 required=True, dest="output", default=False,
                                 help="path to the output dir")

    argument_parser.add_argument("--sysAutoruns", action="store",
                                 required=False, dest="sys_autoruns", default=False,
                                 help="dest where the result will be written")

    argument_parser.add_argument('--process1', action="store",
                                 required=False, dest="process1", default=False,
                                 help="path to the input dir")

    argument_parser.add_argument('--process2', action="store",
                                 required=False, dest="process2", default=False,
                                 help="path to the input dir")

    argument_parser.add_argument('--processTimeline', action="store",
                                 required=False, dest="process_timeline", default=False,
                                 help="path to the input dir")

    argument_parser.add_argument('--processInfo', action="store",
                                 required=False, dest="process_info", default=False,
                                 help="path to the input dir")

    argument_parser.add_argument('--processAutoruns', action="store",
                                 required=False, dest="process_autoruns", default=False,
                                 help="path to the input dir")

    return argument_parser


def process_file_in_folder(argument):
    """
    Function to parse all artefacts in a specific folder
    :param argument: (args)
    :return:
    """
    parser = ProcessParser(argument.output)
    search = [f for f in os.listdir(argument.input_dir) if
              re.search(r'autoruns\.csv$', f)]
    if search:
        relative_file_path = Path(os.path.join(argument.input_dir, search[0]))
        absolute_file_path = relative_file_path.absolute()  # absolute is a Path object

        parser.parse_autoruns_sysinternals(absolute_file_path)

    search = [f for f in os.listdir(argument.input_dir) if
              re.search(r'processes1\.csv$', f)]
    if search:
        relative_file_path = Path(os.path.join(argument.input_dir, search[0]))
        absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
        parser.parse_process1(absolute_file_path)

    search = [f for f in os.listdir(argument.input_dir) if
              re.search(r'processes2\.csv$', f)]
    if search:
        relative_file_path = Path(os.path.join(argument.input_dir, search[0]))
        absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
        parser.parse_process2(absolute_file_path)

    search = [f for f in os.listdir(argument.input_dir) if
              re.search(r'(GetSamples_timeline\.csv|Process_timeline\.csv)', f)]
    if search:
        relative_file_path = Path(os.path.join(argument.input_dir, search[0]))
        absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
        parser.parse_process_timeline(absolute_file_path)

    search = [f for f in os.listdir(argument.input_dir) if
              re.search(r'(GetSamples_sampleinfo\.csv|Process_sampleinfo\.csv)', f)]
    if search:
        relative_file_path = Path(os.path.join(argument.input_dir, search[0]))
        absolute_file_path = relative_file_path.absolute()  # absolute is a Path object

        parser.parse_process_infos(absolute_file_path)

    search = [f for f in os.listdir(argument.input_dir) if
              re.search(r'(GetSamples_autoruns\.xml|Process_Autoruns\.xml)', f)]
    if search:
        relative_file_path = Path(os.path.join(argument.input_dir, search[0]))
        absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
        parser.parse_process_autoruns(absolute_file_path)


if __name__ == '__main__':

    ps = parse_args()
    args = ps.parse_args()
    process_parser = ProcessParser(args.output)
    if args.input_dir:
        process_file_in_folder(args)
    if args.sys_autoruns:
        process_parser.parse_autoruns_sysinternals(args.sys_autoruns)
    if args.process1:
        process_parser.parse_process1(args.process1)
    if args.process2:
        process_parser.parse_process2(args.process2)
    if args.process_timeline:
        process_parser.parse_process_timeline(args.process_timeline)
    if args.process_info:
        process_parser.parse_process_infos(args.process_info)
    if args.process_autoruns:
        process_parser.parse_process_autoruns(args.process_autoruns)

