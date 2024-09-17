#!/usr/bin/python3
import argparse
import json
import os
import re
import sys
import traceback
from pathlib import Path
from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
import datetime
import csv


class RegistryParser:
    """
       Class to Registry
       """

    def __init__(self) -> None:
        """
        The constructor for RegistryParser
        """
        pass

    def parse_amcache_regpy(self, file_path, dir_out):
        """
        Main function to parse amcache with regippy
        :param file_path: str : path to the amcache file
        :param dir_out: str : path to result folder
        :return:
        """
        hv_name = os.path.basename(file_path)
        reg = RegistryHive(file_path)
        path_out_csv = os.path.join(dir_out, "{}_regpy.csv".format(hv_name))
        path_out_json = os.path.join(dir_out, "{}_regpy.json".format(hv_name))
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            entry = parsed.get("amcache", [])
            l_not_sorted = []
            header_list = ["Date", "Time", "Name", "Hash"]
            for val in entry:
                timestamp = val.get("timestamp")
                name = val.get("original_file_name", "-")
                sha1 = val.get("sha1", "-")
                output = "{}|{}|{}".format(timestamp, name, sha1)
                l_not_sorted.append(output)

            if l_not_sorted:
                self.format_and_write_to_csv(path_out_csv, l_not_sorted, header_list)
        except:
            print(traceback.format_exc())

    def parse_software_regpy(self, file_path, dir_out):
        """
        Main function to parse software hive with regippy
        :param file_path: str : path to the software file
        :param dir_out: str : path to result folder
        :return:
        """
        print("parsing SOFTWARE")
        hv_name = os.path.basename(file_path)
        reg = RegistryHive(file_path)
        path_out_csv = os.path.join(dir_out, "{}_regpy.csv".format(hv_name))
        path_out_json = os.path.join(dir_out, "{}_regpy.json".format(hv_name))
        # Iterate over a registry hive recursively:
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            with open(path_out_csv, 'w') as file_out:
                for value in parsed.values():
                    for key in value:
                        if type(key) == dict:
                            key = json.dumps(key).replace(",", "|").replace("{", "|").replace("}", "|")
                        file_out.write(key)
                        file_out.write("\n")
        except:
            print(traceback.format_exc())

    def parse_system_regpy(self, file_path, dir_out):
        """
        Main function to parse system hive with regippy
        :param file_path: str : path to the software file
        :param dir_out: str : path to result folder
        :return:
        """
        print("parsing SYSTEM")
        hv_name = os.path.basename(file_path)
        reg = RegistryHive(file_path)
        path_out_csv = os.path.join(dir_out, "{}_regpy.csv".format(hv_name))
        path_out_json = os.path.join(dir_out, "{}_regpy.json".format(hv_name))
        # Iterate over a registry hive recursively:
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            with open(path_out_csv, 'w') as file_out:
                for value in parsed.values():
                    for key in value:
                        if type(key) == dict:
                            key = json.dumps(key).replace(",", "|").replace("{", "|").replace("}", "|")
                        file_out.write(key)
                        file_out.write("\n")
        except:
            print(traceback.format_exc())

    def parse_security_regpy(self, file_path, dir_out):
        """
        Main function to parse security hive with regippy
        :param file_path: str : path to the software file
        :param dir_out: str : path to result folder
        :return:
        """
        print("parsing SECURITY")
        hv_name = os.path.basename(file_path)
        reg = RegistryHive(file_path)
        # Iterate over a registry hive recursively:
        path_out_csv = os.path.join(dir_out, "{}_regpy.csv".format(hv_name))
        path_out_json = os.path.join(dir_out, "{}_regpy.json".format(hv_name))
        # Iterate over a registry hive recursively:
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            with open(path_out_csv, 'a') as file_out:
                for value in parsed.values():
                    for key in value:
                        if type(key) == dict:
                            key = json.dumps(key).replace(",", "|").replace("{", "|").replace("}", "|")
                        file_out.write(key)
                        file_out.write("\n")
        except:
            print(traceback.format_exc())

    def parse_ntuser_regpy(self, file_path, dir_out):
        """
        Main function to parse ntuser hive with regippy
        :param file_path: str : path to the ntuser file
        :param dir_out: str : path to result folder
        :return:
        """
        #Not done yet
        pass

    def parse_shimcash_regpy(self, file_path, dir_out):
        """
        Main function to parse shimcash app compat hive with regippy
        :param file_path: str : path to the appcompat file
        :param dir_out: str : path to result folder
        :return:
        """
        #Not done yet
        pass

    def parse_all_regpy(self, dir_to_reg, out_folder):
        """
        Main function to parse all hive with regippy
        :param dir_to_reg: str : path to the folder containing all hives to parse
        :param out_folder: str : path to result folder
        :return:
        """
        search = [f for f in os.listdir(dir_to_reg) if
                  re.search(r'Amcache\.hve$', f)]
        if search:
            relative_file_path = Path(os.path.join(dir_to_reg, search[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            reg_parser.parse_amcache_regpy(absolute_file_path, out_folder)

        search = [f for f in os.listdir(dir_to_reg) if
                  re.search(r'SECURITY', f)]
        if search:
            relative_file_path = Path(os.path.join(dir_to_reg, search[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            reg_parser.parse_security_regpy(absolute_file_path, out_folder)

        search = [f for f in os.listdir(dir_to_reg) if
                  re.search(r'SYSTEM', f)]
        if search:
            relative_file_path = Path(os.path.join(dir_to_reg, search[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            reg_parser.parse_system(absolute_file_path, out_folder)
        '''


        search = [f for f in os.listdir(dir_to_reg) if
                  re.search(r'SOFTWARE', f)]
        if search:
            relative_file_path = Path(os.path.join(dir_to_reg, search[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            reg_parser.parse_software(absolute_file_path, out_folder)
        '''

    def format_list_user_friendly(self, list_to_format):
        """
        To format a list to a human-readable format DATE|TIME|ETC|ETC
        :param list_to_format: list : list to be formated
        :return: list : human readble sorted list
        """
        list_sorted = []
        lines = sorted(list_to_format, key=lambda line: line.split("|")[0])
        for line_sorted in lines:
            splited_line = line_sorted.split("|")
            splited_line[0] = splited_line[0].replace("T", "|").split(".")[0]
            list_sorted.append("|".join(splited_line))
        return list_sorted

    def write_report_as_csv_file(self, path_to_file, l_content):
        """
        Function to write a report  on a file.
        Parameters:
            path_to_file (str) path of the file to write to
            l_content (list(str)) a list of string
        """
        try:
            with open(path_to_file, 'a') as obs_file:
                for line in l_content:
                    obs_file.write(line)
                    obs_file.write("\n")
        except Exception:
            print(traceback.format_exc())

    def format_and_write_to_csv(self, out_file, l_to_process, header):
        """
        To format a list to a nice human-readable csv
        :param out_file: str : path to file where the result will be written
        :param l_to_process: list : list to be formated to human-readble
        :param header: list : header that will be writted at the top of the csv file
        :return:
        """
        l_formated = self.format_list_user_friendly(l_to_process)
        l_formated.insert(0, "|".join(header))
        self.write_report_as_csv_file(out_file, l_formated)

    def convert_epoch_and_sort(self, in_file):
        """sort a CSV by date and convert epoch ts to current.

        Args:
            in_file (str): path to csv file.
        """

        with open(in_file, 'r') as file:
            next(file)
            reader = csv.reader(file, delimiter='|')
            lines = list(reader)

            def sort_key(ligne):
                try:
                    timestamp = int(ligne[0])
                    return datetime.datetime.fromtimestamp(timestamp)
                except:
                    return datetime.datetime.now()

            lines.sort(key=sort_key, reverse=False)
            for line in lines:
                try:
                    timestamp = int(line[0])
                    formatted_timestamp = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d|%H:%M:%S")
                    line[0] = formatted_timestamp
                except:
                    continue
        return lines

    def parse_hive_from_rr(self, hv_name, path_to_hive, path_to_result_dir):
        try:
            processed = self.convert_epoch_and_sort(path_to_hive)

            with open(os.path.join(path_to_result_dir, "{}.csv".format(hv_name)), 'a') as res_file:
                writer = csv.writer(res_file, delimiter='|')
                writer.writerows(processed)

            if "system" in hv_name.lower():
                l_shimcache = self.get_shimcache_from_system_rr(processed)

                with open(os.path.join(path_to_result_dir, "appcompat.csv"), 'a') as res_file:
                    for line in l_shimcache:
                        res_file.write(line)
                        res_file.write("\n")
        except:
            print(traceback.format_exc())

    def get_shimcache_from_system_rr(self, l_system):
        l_shimcache = ["DATE|TIME|ENTRY"]
        for line in l_system:
            if len(line) >= 4:
                if "AppCompatCache" in line[4]:
                        date_time = line[0]
                        entry = line[4].replace("M...", "").replace("AppCompatCache", "").lstrip()
                        l_shimcache.append("{}|{}".format(date_time, entry))
        return l_shimcache


def verify(regfile, reg_type):
    """
    To check if hive is ok
    :param regfile: str : path to the registry file
    :param reg_type: str: type of hive
    :return: bool
    """
    reg_name = os.path.basename(regfile).lower()
    if reg_type.lower() not in reg_name:
        while True:
            print("reg profile {} doesn't seems to be appropriate for {} file".format(reg_type, reg_name))
            resp = input("do you wish to continu anyway ? (N/n-Y/y) : N ")
            if resp.lower() == "n":
                sys.exit()
            elif resp.lower() == "y":
                return True
            else:
                continue
