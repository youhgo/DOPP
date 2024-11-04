#!/usr/bin/python3
import logging as log
import os
import traceback
import argparse
from pathlib import Path
import re
import json

class NetWorkParser:
    """
       Class parse network files to human-readable csv DATE|TIME|ETC|ETC
    """

    def __init__(self, output_directory, machine_name="-", is_json=False,  json_directory="", separator="|") -> None:
        """
        The constructor for NetWorkParser class
        :param output_directory: str : path to where csv results will be written
        :param is_json: Bool : set yes to add a json output file
        :param machine_name: str: name of the machine
        :param json_directory: str: path to where json results will be written
        :param artefact_config: dict: artefact config
        :param separator: str: csv separator default is pipe
        """
        self.separator = separator
        self.dir_out = output_directory
        if json_directory:
            self.json_dir_out = json_directory
        else:
            self.json_dir_out = output_directory

        self.is_json = is_json
        self.machine_name = machine_name

    def parse_tcpvcon(self, file_path):
        """
        To parse tcpvcon result file
        :param file_path: str : path to tcpvcon result file
        :return:
        """
        l_res = []
        header_list = ["Protocol", "Process", "PID", "State", "Local Addr", "Distant Addr\n"]
        reg = re.compile(r'^(TCP)|(UDP)')
        if self.is_json:
            tcpvcon_result_file_json = open(os.path.join(self.json_dir_out, "tcpvcon_parsed.json"),"a")
        try:
            with open(file_path, 'r') as file_in:
                for line in file_in.readlines():
                    l_col = line.split(',')
                    if l_col:
                        if re.match(reg, str(l_col[0])):
                            protocol = "-"
                            process = "-"
                            pid = "-"
                            state = "-"
                            local_addr = "-"
                            distant_addr ="-"
                            if l_col[0]:
                                protocol = l_col[0]
                            if l_col[1]:
                                process = l_col[1]
                            if l_col[2]:
                                pid = l_col[2]
                            if l_col[3]:
                                state = l_col[3]
                            if l_col[4]:
                                local_addr = l_col[4]
                            if l_col[5]:
                                distant_addr = l_col[5]

                            #formated_l.append(line.replace(",", "{}".format(self.separator)))
                            l_res.append("{}{}{}{}{}{}{}{}{}{}{}".format(protocol, self.separator,
                                                                         process, self.separator,
                                                                         pid, self.separator,
                                                                         state, self.separator,
                                                                         local_addr, self.separator,
                                                                         distant_addr))
                            if self.is_json:
                                json_line = {
                                    "machine_name": "{}".format(self.machine_name),
                                    "protocol": "{}".format(process),
                                    "pid": "{}".format(pid),
                                    "state": "{}".format(state),
                                    "local_address": "{}".format(local_addr),
                                    "distant_address": "{}".format(distant_addr),
                                }
                                json.dump(json_line, tcpvcon_result_file_json, indent=4)


            with open(os.path.join(self.dir_out, "tcpvcon_parsed.csv"), 'a') as out_file:
                l_res.insert(0, "{}".format(self.separator).join(header_list))
                for entry in l_res:
                    out_file.write(entry)

        except Exception:
            print(traceback.format_exc())

    def parse_netstat(self, file_path):
        """
        To parse netstat result file
        :param file_path: str : path to netstat result file
        :return:
        """
        l_res = []
        header_list = ["Protocol", "Local Addr", "Distant Addr", "State", "-"]
        reg = re.compile(r'^(TCP)|(UDP)')
        if self.is_json:
            netstat_result_file_json = open(os.path.join(self.json_dir_out, "netstat_parsed.json"),"a")
        try:
            with open(file_path, 'r', encoding="utf8", errors='ignore') as file_in:
                for line in file_in.readlines():
                    l_col = line.split()
                    if l_col:
                        if re.match(reg, str(l_col[0])):
                            #l_res.append(" ".join(l_col).replace(" ", "{}".format(self.separator)))
                            protocol = "-"
                            pid = "-"
                            state = "-"
                            local_addr = "-"
                            distant_addr = "-"
                            if len(l_col) == 5:
                                if l_col[0]:
                                    protocol = l_col[0]
                                if l_col[1]:
                                    local_addr = l_col[1]
                                if l_col[2]:
                                    distant_addr = l_col[2]
                                if l_col[3]:
                                    state = l_col[3]
                                if l_col[4]:
                                    pid = l_col[4]

                            if len(l_col) == 4:
                                if l_col[0]:
                                    protocol = l_col[0]
                                if l_col[1]:
                                    local_addr = l_col[1]
                                if l_col[2]:
                                    distant_addr = l_col[2]
                                if l_col[3]:
                                    pid = l_col[3]
                                state = "Unknown"

                            # formated_l.append(line.replace(",", "{}".format(self.separator)))
                            l_res.append("{}{}{}{}{}{}{}{}{}".format(protocol, self.separator,
                                                                           pid, self.separator,
                                                                           state, self.separator,
                                                                           local_addr, self.separator,
                                                                           distant_addr))
                            if self.is_json:
                                json_line = {
                                    "machine_name": "{}".format(self.machine_name),
                                    "pid": "{}".format(pid),
                                    "state": "{}".format(state),
                                    "local_address": "{}".format(local_addr),
                                    "distant_address": "{}".format(distant_addr),
                                }
                                json.dump(json_line, netstat_result_file_json, indent=4)

            with open(os.path.join(self.dir_out, "netstat_parsed.csv"), 'a') as out_file:
                l_res.insert(0, "{}".format(self.separator).join(header_list))
                for entry in l_res:
                    out_file.write(entry)
                    out_file.write('\n')

        except Exception:
            print(traceback.format_exc())

    def parse_all(self, input_dir):
        """
        Main function to parse networks files
        :param input_dir: str : dir where files to be parsed are located
        :param output_dir: str : dir where results files will be written
        :return:
        """
        search_netstat = [f for f in os.listdir(input_dir) if re.search(r'netstat\.txt$', f)]
        if search_netstat:
            relative_file_path = Path(os.path.join(input_dir, search_netstat[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_netstat(absolute_file_path)

        search_tcpvcon = [f for f in os.listdir(input_dir) if
                  re.search(r'Tcpvcon\.txt$', f)]
        if search_tcpvcon:
            relative_file_path = Path(os.path.join(input_dir, search_tcpvcon[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_tcpvcon(absolute_file_path)

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Parser for networks artefacts collected by DFIR ORC'))

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

    parser = NetWorkParser(args.output_dir, False)
    parser.parse_all(args.input_dir)