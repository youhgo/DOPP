#!/usr/bin/python3
import logging as log
import os
import traceback
import argparse
from pathlib import Path
import re

class NetWorkParser:
    """
       Class parse network files to human-readable csv DATE|TIME|ETC|ETC
    """

    def __init__(self) -> None:
        """
        The constructor for NetWorkParser class.
        """
        pass

    def parse_tcpvcon(self, file_path, dir_out):
        """
        To parse tcpvcon result file
        :param file_path: str : path to tcpvcon result file
        :param dir_out: str : path to dir where result file will be written
        :return:
        """
        formated_l = []
        header_list = ["Protocol", "Process", "-", "State", "Local Addr", "Distant Addr\n"]
        reg = re.compile(r'^(TCP)|(UDP)')
        try:
            with open(file_path, 'r') as file_in:
                for line in file_in.readlines():
                    l_col = line.split(',')
                    if l_col:
                        if re.match(reg, str(l_col[0])):
                            formated_l.append(line.replace(",", "|"))

            with open(os.path.join(dir_out, "tcpvcon-parsed.csv"), 'a') as out_file:
                formated_l.insert(0, "|".join(header_list))
                for entry in formated_l:
                    out_file.write(entry)

        except Exception:
            print(traceback.format_exc())

    def parse_netstat(self, file_path, dir_out):
        """
        To parse netstat result file
        :param file_path: str : path to netstat result file
        :param dir_out: str : path to dir where result file will be written
        :return:
        """
        formated_l = []
        header_list = ["Protocol", "Local Addr", "Distant Addr", "State", "-"]
        reg = re.compile(r'^(TCP)|(UDP)')
        try:
            with open(file_path, 'r', encoding="utf8", errors='ignore') as file_in:
                for line in file_in.readlines():
                    l_col = line.split()
                    if l_col:
                        if re.match(reg, str(l_col[0])):
                            formated_l.append(" ".join(l_col).replace(" ", "|"))

            with open(os.path.join(dir_out, "netstat-parsed.csv"), 'a') as out_file:
                formated_l.insert(0, "|".join(header_list))
                for entry in formated_l:
                    out_file.write(entry)
                    out_file.write('\n')

        except Exception:
            print(traceback.format_exc())

    def parse_all(self, input_dir, output_dir):
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
            self.parse_netstat(absolute_file_path, output_dir)

        search_tcpvcon = [f for f in os.listdir(input_dir) if
                  re.search(r'Tcpvcon\.txt$', f)]
        if search_tcpvcon:
            relative_file_path = Path(os.path.join(input_dir, search_tcpvcon[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_tcpvcon(absolute_file_path, output_dir)

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

    parser = NetWorkParser()
    parser.parse_all(args.input_dir, args.output_dir)