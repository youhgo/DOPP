import argparse
import datetime
import json
import subprocess
import sys
import os
import traceback
import csv
import re
from fileinput import filename

from pathlib import Path
from .classes import FileManager, Extractor, LoggerManager
from .parsers import (EventParser, ProcessParser, PrefetchParser, NetWorkParser, RegistryParser, LnkParser,
                      MaximumPlasoParserJson, DiskParser)

# TODO: Replay all hives transactions
# TODO: Parse browser History
# TODO: CREATE JSON OUTPUT FOR EVERY PARSER
# TODO: AD_computer.csv to parse

class OrcPaser:
    """
    Main class to launch all tools
    """

    def __init__(self, path_to_orc, path_to_work_dir, case_name, master_id="", parser_config="", artefact_config="") -> None:
        """
        Constructer for Orc Parser class
        :param path_to_orc: str : path to archive
        :param path_to_work_dir: str : path to working directory (where all processed file will be written)
        :param case_name: str: name of the case
        :param master_id: celery process id
        :param config: json/dict parsers config
        """
        self.tool_path = os.environ.get("TOOL_PATH", "python-docker/DOPP_MODULE/outils")
        self.evtx_dump_path_old = os.path.join(self.tool_path, "evtx_dump")
        self.evtx_dump_path = os.path.join(self.tool_path, "evtx_dump")
        self.ese_analyst_path = os.path.join(self.tool_path, "ese-analyst/ese2csv.py")
        self.ese_analyst_plugin_path = os.path.join(self.tool_path, "ese-analyst/srudb_plugin.py")
        self.hayabusa_tool_path = os.path.join(self.tool_path, "hayabusa-2.17.0-linux-intel/hayabusa-2.17.0-lin-x64-gnu")
        self.clean_duplicates_tool_path = os.path.join(self.tool_path, "clean_duplicate.sh")

        self.master_id = master_id

        self.case_name = case_name

        self.path_to_orc = path_to_orc
        self.orc_name = os.path.splitext(os.path.basename(path_to_orc))[0].replace("DFIR-ORC_", "") # pc1


        self.current_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.orc_final_name = self.orc_name + "_" + self.current_date

        self.work_dir = os.path.join(path_to_work_dir, case_name)
        self.orc_folder = os.path.join(self.work_dir, self.orc_final_name)
        self.extracted_dir = os.path.join(self.orc_folder, "extracted")
        self.parsed_dir = os.path.join(self.orc_folder, "parsed")

        self.evt_dir = os.path.join(self.parsed_dir, "event")

        self.processDir = os.path.join(self.parsed_dir, "process")
        self.netWorkDir = os.path.join(self.parsed_dir, "network")
        self.powershellDir = os.path.join(self.parsed_dir, "powershell")

        self.hiveDir = os.path.join(self.parsed_dir, "hives")
        self.hiveDirRR = os.path.join(self.hiveDir, "hives_regripper")
        self.hiveDirRegipy = os.path.join(self.hiveDir, "hives_regipy")

        self.mftDir = os.path.join(self.parsed_dir, "mft")
        self.artefactsDir = os.path.join(self.parsed_dir, "artefact")
        self.prefetchDir = os.path.join(self.parsed_dir, "prefetch")
        self.srumDir = os.path.join(self.parsed_dir, "SRUM")
        self.timelineDir = os.path.join(self.parsed_dir, "timeline")

        self.debugDir = os.path.join(self.parsed_dir, "debug")
        self.txtLogDir = os.path.join(self.parsed_dir, "textLogs")
        self.logDir = os.path.join(path_to_work_dir, "execution_logs")
        self.lnkDir = os.path.join(self.parsed_dir, "lnk")

        self.result_parsed_dir = os.path.join(self.parsed_dir, "parsed_for_human")
        self.json_dir = os.path.join(self.parsed_dir, "json_results")
        self.logger_run = ""
        self.logger_debug = ""

        self.running_log_file_path = os.path.join(self.logDir, "{}_running.log".format(self.master_id))
        self.debug_log_file_path = os.path.join(self.logDir, "{}_debug.log".format(self.master_id))

        if parser_config:
            self.parser_config = parser_config
        else:
            from .classes.ConfigManager import ConfigManager
            cf_manager = ConfigManager()
            self.parser_config = cf_manager.load_config("/python-docker/DOPP_MODULE/config/parserDefaultConfig.json")

        if artefact_config:
            self.artefact_config = artefact_config
        else:
            from .classes.ConfigManager import ConfigManager
            cf_manager = ConfigManager()
            self.artefact_config = cf_manager.load_config("/python-docker/DOPP_MODULE/config/artefact_name_config.json")

    def clean_archive_name(self, pattern, og_name):
        new_name = re.sub(pattern, '', og_name)
        return new_name

    def initialise_working_directories(self):
        """
            To create directories where the results will be written
        """
        try:
            os.makedirs(self.work_dir, exist_ok=True)
            os.makedirs(self.orc_folder, exist_ok=True)
            os.makedirs(self.extracted_dir, exist_ok=True)
            os.makedirs(self.parsed_dir, exist_ok=True)

            os.makedirs(self.evt_dir, exist_ok=True)
            os.makedirs(self.processDir, exist_ok=True)
            os.makedirs(self.netWorkDir, exist_ok=True)
            os.makedirs(self.powershellDir, exist_ok=True)

            os.makedirs(self.hiveDir, exist_ok=True)
            os.makedirs(self.hiveDirRR, exist_ok=True)
            os.makedirs(self.hiveDirRegipy, exist_ok=True)

            os.makedirs(self.mftDir, exist_ok=True)
            os.makedirs(self.artefactsDir, exist_ok=True)
            os.makedirs(self.prefetchDir, exist_ok=True)
            os.makedirs(self.srumDir, exist_ok=True)
            os.makedirs(self.timelineDir, exist_ok=True)
            os.makedirs(self.debugDir, exist_ok=True)
            os.makedirs(self.logDir, exist_ok=True)
            os.makedirs(self.txtLogDir, exist_ok=True)
            os.makedirs(self.lnkDir, exist_ok=True)
            os.makedirs(self.result_parsed_dir, exist_ok=True)
            os.makedirs(self.json_dir, exist_ok=True)

            self.logger_run = LoggerManager.LoggerManager("running", self.running_log_file_path, "INFO")
            self.logger_debug = LoggerManager.LoggerManager("debug", self.debug_log_file_path, "DEBUG")

        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

    def get_dict_value_as_list(self, config):
        all_values = list(config.values())
        final_list = []
        for l_value in all_values:
            final_list.extend(l_value)
        return final_list

    def search_and_copy_artefacts_from_config(self, artefact, out_dir):
        mngr = FileManager.FileManager()
        all_file_to_search = self.get_dict_value_as_list(self.artefact_config.get("artefacts", {}).get(artefact, {}))
        for f_patern in all_file_to_search:
            l_file = mngr.recursive_file_search(self.extracted_dir, f_patern)
            if l_file:
                for file in l_file:
                    mngr.copy_file_to_dest(file, out_dir)

    def extract(self):
        """
         to extract orc archives
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[EXTRACTING] archives")
            extr = Extractor.OrcExtractor()
            cleaned_name_archive = self.clean_archive_name(r'__\d+$', self.path_to_orc)
            root, filename = os.path.split(cleaned_name_archive)  # /blabla/ - orc1.7z
            filename_wo_ext, file_ext = os.path.splitext(filename)  # /blabla/orc1
            self.logger_run.print_info_start_sub_1("{} {} {}".format(filename_wo_ext, file_ext, filename))

            if file_ext == ".7z":
                self.logger_run.print_info_start_sub_1("Extracting {} ".format(self.path_to_orc))
                extr.extract_7z_archive(self.path_to_orc, self.extracted_dir)
            if file_ext == ".zip":
                self.logger_run.print_info_start_sub_1("Extracting {} ".format(self.path_to_orc))
                extr.extract_zip_archive(self.path_to_orc, self.extracted_dir)

            self.logger_run.print_info_finished_sub_1("[EXTRACTING] archive")

        except:
            self.logger_run.print_info_failed_sub_1("[EXTRACTING] archive")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def clean(self):
        """
         to rename all files
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[CLEANING] useless files")
            mngr = FileManager.FileManager()
            mngr.rename_nested_folder(self.extracted_dir)
            self.logger_run.print_info_finished_sub_1("[CLEANING] useless files")
        except:
            self.logger_run.print_info_failed_sub_1("[CLEANING] useless files")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def move_txt_artefacts(self):
        """
        to move artefact that have text format
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[MOVING] txt artefacts")

            self.search_and_copy_artefacts_from_config("orc", self.debugDir)
            #self.search_and_copy_artefacts_from_config("system", self.parsed_dir)
            self.search_and_copy_artefacts_from_config("network", self.netWorkDir)
            self.search_and_copy_artefacts_from_config("process", self.processDir)
            self.search_and_copy_artefacts_from_config("powershell", self.powershellDir)
            self.search_and_copy_artefacts_from_config("disk", self.mftDir)

            mngr = FileManager.FileManager()
            ext_text_log_dir = os.path.join(self.extracted_dir, "TextLogs")
            ext_diver_dir_path = os.path.join(ext_text_log_dir, "divers")
            mngr.copy_folder_to_dest(ext_diver_dir_path, self.txtLogDir)

            ext_hives_log_dir_path = os.path.join(ext_text_log_dir, "hives_log")
            mngr.copy_folder_to_dest(ext_hives_log_dir_path, self.txtLogDir)

            self.logger_run.print_info_finished_sub_1("[MOVING] txt artefacts")

        except:
            self.logger_run.print_info_failed_sub_1("[MOVING] txt artefacts")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_system_info(self):
        self.logger_run.print_info_start_sub_1("[PARSING] [SYSTEMINFO]")
        try:
            mngr = FileManager.FileManager()
            all_file_to_search = self.artefact_config.get("artefacts", {}).get("system", {}).get("system_info", "")
            for f_patern in all_file_to_search:
                l_file = mngr.recursive_file_search(self.extracted_dir, f_patern)
                if l_file:
                    for file in l_file:
                        out_txt_file_path = os.path.join(self.parsed_dir, "systeminfo.txt")
                        out_json_file_path = os.path.join(self.parsed_dir, "systeminfo.json")
                        out_txt_file_stream = open(out_txt_file_path, 'a')
                        out_json_file_stream = open(out_json_file_path, 'a')

                        with open(file, 'r') as system_info_file:
                            reader = csv.reader(system_info_file)
                            header = next(reader)
                            data = []
                            for line in reader:
                                line_dict = dict(zip(header, line))
                                data.append(line_dict)
                                for i, value in enumerate(line):
                                    out_txt_file_stream.write("{}:{}".format(header[i], value))
                                    out_txt_file_stream.write("\n")

                            json.dump(data, out_json_file_stream, indent=4)
                            out_txt_file_stream.close()
                            out_json_file_stream.close()
                            self.logger_run.print_info_finished_sub_1("[CONVERTING] [EVTX] [JSON]")
                else:
                    self.logger_run.print_info_failed_sub_1("SYSTEMINFO FILE NOT FOUND")

        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [SYSTEMINFO]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def convert_evtx_to_json(self):
        """
        to Launch evtdump for converting evtx file to json files
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[CONVERTING] [EVTX] [JSON]")

            mngr = FileManager.FileManager()
            evtx_f_patter = self.artefact_config.get("artefacts", {}).get("event_logs", {}).get("evtx", "")
            for patern in evtx_f_patter:
                all_evt = mngr.recursive_file_search(self.extracted_dir, patern)
                if all_evt:
                    for evt in all_evt:
                        try:
                            evt_name = os.path.basename(evt)
                            evt_name_wo_ext = os.path.splitext(evt_name)[0]
                            evt_json_name = evt_name_wo_ext + ".json"
                            self.logger_run.print_info_start_sub_2("Converting {} to json".format(evt_name_wo_ext))

                            out_file = os.path.join(self.evt_dir, evt_json_name)
                            my_cmd = ["{}".format(self.evtx_dump_path), "{}".format(evt)]
                            with open(out_file, "w") as outfile:
                                subprocess.run(my_cmd, stdout=outfile)

                            self.logger_run.print_info_finished_sub_2("Converting {} to json".format(evt_name_wo_ext))


                        except:
                            self.logger_run.print_info_failed_sub_2("Converting {} to json".format(evt_name))
                            self.logger_debug.print_error_failed(traceback.format_exc())

            self.logger_run.print_info_finished_sub_1("[CONVERTING] [EVTX] [JSON]")
        except:
            self.logger_run.print_info_failed_sub_1("[CONVERTING] [EVTX] [JSON]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_evtx(self):
        """
        To parse json evtx files to the human readable format Date|Time|ID|ETC
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [EVTX]")
            evtparser = EventParser.EventParser(self.evt_dir, self.result_parsed_dir)
            evtparser.parse_all()
            self.logger_run.print_info_finished_sub_1("[PARSING] [EVTX]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [EVTX]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_process(self):
        """
        To parse processes results files to the human readable format Date|Time|ID|ETC
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [PROCESSES]")

            proc_parser = ProcessParser.ProcessParser(self.result_parsed_dir, True, self.processDir)
            proc_parser.parse_all(self.processDir)

            self.logger_run.print_info_finished_sub_1("[PARSING] [PROCESSES]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [PROCESSES]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_network(self):
        """
        To parse network results files to the human-readable format Date|Time|ID|ETC
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [NETWORK]")
            nt_parser = NetWorkParser.NetWorkParser()
            nt_parser.parse_all(self.extracted_dir, self.result_parsed_dir)
            self.logger_run.print_info_finished_sub_1("[PARSING] [NETWORK]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [NETWORK]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_prefetch(self, is_volume=False, is_json=True):
        """
        To parse pf files to the human readable format Date|Time|ID|ETC
        :return:
        """
        try:
            pf_re = re.compile(r'.*.pf$')
            self.logger_run.print_info_start_sub_1("[PARSING] [PREFETCH]")
            mngr = FileManager.FileManager()
            pf_parser = PrefetchParser.PrefetchParser()
            prefetch_final_file = os.path.join(self.result_parsed_dir, "prefetchs.csv")

            l_pf_files = mngr.recursive_file_search(self.extracted_dir, pf_re)
            if l_pf_files:
                for pf_file in l_pf_files:
                    self.logger_run.print_info_start_sub_2("[PARSING] {}".format(pf_file))
                    root, pf_file_name = os.path.split(pf_file)
                    output = pf_parser.parse_file(pf_file, is_volume)

                    if output:
                        #pf_out_file_csv = os.path.join(self.prefetchDir, "{}.csv".format(pf_file_name))
                        pf_out_file_json = os.path.join(self.prefetchDir, "{}.json".format(pf_file_name))
                        pf_parser.outputResults(output, prefetch_final_file)
                        pf_parser.outputResults(output, pf_out_file_json, True)

            else:
                self.logger_run.print_info_finished_sub_2("[NO] [PREFETCH] [FOUND]")

            self.logger_run.print_info_finished_sub_1("[PARSING] [PREFETCH]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [PREFETCH]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_srum(self):
        """
        To parse srum files to the human readable format Date|Time|ID|ETC
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [SRUM]")
            mngr = FileManager.FileManager()
            srum_paterns = self.artefact_config.get("artefacts", {}).get("files", {}).get("SRUM", "")
            for srum_patern in srum_paterns:
                l_srum_files = mngr.recursive_file_search(self.extracted_dir, srum_patern)
                if l_srum_files:
                    for srum_file in l_srum_files:
                        my_cmd = ["python3", "{}".format(self.ese_analyst_path), "--plugin",
                                  "{}".format(self.ese_analyst_plugin_path),
                                  "-o", "{}".format(self.srumDir), "{}".format(srum_file)]
                        # need to find a way to use this as a library
                        subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_1("[PARSING] [SRUM]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [SRUM]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_hives_rr(self):
        """
        To parse systems hives files with RegRipper
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [HIVE] [REGRIPPER]")

            l_hive_to_search = self.get_dict_value_as_list(self.artefact_config.get("artefacts", {}).get("hives", []))
            mngr = FileManager.FileManager()
            reg_parser = RegistryParser.RegistryParser()

            for hive_patern in l_hive_to_search:
                hive_files = mngr.recursive_file_search(self.extracted_dir, hive_patern)
                if hive_files:
                    for hive_file in hive_files:
                        hv_name = os.path.basename(hive_file)
                        self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))

                        out_file = os.path.join(self.hiveDirRR, hv_name.replace("*", "")+".txt")
                        try:
                            my_cmd = ["rip.pl", "-r", "{}".format(hive_file), "-at", "-g"]
                            with open(out_file, "a") as outfile:
                                subprocess.run(my_cmd, stdout=outfile)

                            reg_parser.parse_hive_from_rr(hv_name, out_file, self.result_parsed_dir)
                            self.logger_run.print_info_finished_sub_2("parsing {}".format(hv_name))
                        except:
                            self.logger_run.print_info_failed_sub_2("parsing {}".format(hv_name))
                            self.logger_debug.print_error_failed(traceback.format_exc())


            self.logger_run.print_info_finished_sub_1("[PARSING] [HIVE] [REGRIPPER]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [HIVE] [REGRIPPER]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_system_hives_regipy(self):
        """
        To parse systems hives files with Regipy
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [SYTEM HIVE] [REGIPY]")
            reg_parser = RegistryParser.RegistryParser()
            mngr = FileManager.FileManager()

            secu_hive_paterns = self.artefact_config.get("artefacts", {}).get("hives", {}).get("SECURITY")
            for secu_hive_patern in secu_hive_paterns:
                security_hive = mngr.recursive_file_search(self.extracted_dir, secu_hive_patern)
                for hv in security_hive:
                    hv_name = os.path.basename(hv)
                    self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))
                    reg_parser.parse_security_regpy(hv, self.hiveDirRegipy)
                    self.logger_run.print_info_finished_sub_2("parsing {}".format(hv_name))

            system_hive_paterns = self.artefact_config.get("artefacts", {}).get("hives", {}).get("SYSTEM")
            for system_hive_patern in system_hive_paterns:
                system_hive = mngr.recursive_file_search(self.extracted_dir, system_hive_patern)
                for hv in system_hive:
                    self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))
                    reg_parser.parse_system_regpy(hv, self.hiveDirRegipy)
                    self.logger_run.print_info_finished_sub_2("parsing {}".format(hv_name))

            software_hive_paterns = self.artefact_config.get("artefacts", {}).get("hives", {}).get("SOFTWARE")
            for software_hive_patern in software_hive_paterns:
                software_hive = mngr.recursive_file_search(self.extracted_dir, software_hive_patern)
                for hv in software_hive:
                    self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))
                    self.logger_run.print_info_failed_sub_2("Regipy can't handle SOFTWARE Hive")
                    # reg_parser.parse_software_regpy(hv, self.hiveDirRegipy)

            amcache_hive_paterns = self.artefact_config.get("artefacts", {}).get("hives", {}).get("AMCACHE")
            for amcache_hive_patern in amcache_hive_paterns:
                amcache_hive = mngr.recursive_file_search(self.extracted_dir, amcache_hive_patern)
                for hv in amcache_hive:
                    self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))
                    reg_parser.parse_amcache_regpy(hv, self.result_parsed_dir)
                    self.logger_run.print_info_finished_sub_2("parsing {}".format(hv_name))

            self.logger_run.print_info_finished_sub_1("[PARSING] [HIVE] [REGIPY]")

        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [HIVE] [REGIPY]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_mft(self):
        """
        To parse mft file with analyse mft and parse it to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [MFT]")
            mft_result_file = os.path.join(self.mftDir, "mft.csv")
            mngr = FileManager.FileManager()
            mft_paterns = self.artefact_config.get("artefacts", {}).get("master_file_table", {}).get("MFT")
            for mft_patern in mft_paterns:
                mft_files = mngr.recursive_file_search(self.extracted_dir,mft_patern)
                if mft_files:
                    for mft_file in mft_files:
                        my_cmd = ["analyze_mft", "-f", "{}".format(mft_file),
                                  "-o", "{}".format(mft_result_file)]
                        subprocess.run(my_cmd)
                        mft_parser = DiskParser.DiskParser(self.result_parsed_dir)
                        mft_parser.parse_mft(mft_result_file)
                self.logger_run.print_info_finished_sub_1("[PARSING] [MFT]")
            else:
                self.logger_run.print_info_failed_sub_1("[PARSING] [MFT] File not found")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [MFT]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_usnjrnl(self):
        """
        To parse USN journal to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [USNJRNL]")
            mngr = FileManager.FileManager()
            usn_paterns = self.artefact_config.get("artefacts", {}).get("disk", {}).get("usn_journal")
            for usn_patern in usn_paterns:
                usn_files = mngr.recursive_file_search(self.extracted_dir, usn_patern)
                for usn_file in usn_files:
                    usn_parser = DiskParser.DiskParser(self.result_parsed_dir)
                    usn_parser.parse_usnjrnl(usn_file)
            self.logger_run.print_info_finished_sub_1("[PARSING] [USNJRNL]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [USNJRNL]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def launch_hayabusa_subprocess(self):
        """
        To parse mft file with analyse mft and parse it to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[HAYABUSA]")
            mngr = FileManager.FileManager()
            hayabusa_result_file = os.path.join(self.result_parsed_dir, "hayabusa_timeline.csv")
            evtx_f_patter = self.artefact_config.get("artefacts", {}).get("event_logs", {}).get("evtx", "")
            all_evt = []
            all_evt_dir = []
            for patern in evtx_f_patter:
                all_evt = mngr.recursive_file_search(self.extracted_dir, patern)
            for evt_path in all_evt:
                root, file_name = os.path.split(evt_path)
                if root not in all_evt_dir:
                    all_evt_dir.append(root)
            if all_evt_dir:
                for evt_root_dir in all_evt_dir:
                    my_cmd = ["{}".format(self.hayabusa_tool_path), "csv-timeline", "-d", "{}".format(evt_root_dir),
                              "-o", "{}".format(hayabusa_result_file), "-w"]
                    subprocess.run(my_cmd)

            self.logger_run.print_info_finished_sub_1("[HAYABUSA]")

        except:
            self.logger_run.print_info_failed_sub_1("[HAYABUSA]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def clean_duplicates_subprocess(self, dir_to_clean):

        """
        To clean duplicate lines in results files
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[CLEANING DUPLICATE]")
            my_cmd = ["{}".format(self.clean_duplicates_tool_path), "{}".format(dir_to_clean)]
            subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_1("[CLEANING DUPLICATE]")
        except:
            self.logger_run.print_info_failed_sub_1("[CLEANING DUPLICATE]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def clean_duplicates(self, dir_to_clean):

        """
        To clean duplicates line in file
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[CLEANING DUPLICATE]")
            mngr = FileManager.FileManager()
            l_file = mngr.list_files_recursive(dir_to_clean)
            for file in l_file:
                self.clean_duplicate_in_file(file)
            self.logger_run.print_info_finished_sub_1("[CLEANING DUPLICATE]")
        except:
            self.logger_run.print_info_failed_sub_1("[CLEANING DUPLICATE]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def clean_duplicate_in_file(self, file):
        """
        Remove duplicated line in file
        Args:
        file (str): path to file to be cleaned
        """
        seen_lines = set()
        l_temp = []
        with open(file, 'r') as f:
            for line in f:
                if line not in seen_lines:
                    seen_lines.add(line)
                    l_temp.append(line)

        with open(file, 'w') as f:
            f.writelines(l_temp)

    def convert_epoch_and_sort(self, in_file):
        """Trie un fichier CSV par date décroissante et convertit les timestamps en place.

        Args:
            in_file (str): Le chemin du fichier CSV à modifier.
        """

        with open(in_file, 'r+') as file:
            next(file)
            reader = csv.reader(file, delimiter='|')
            lines = list(reader)

            def cle_tri(line):
                try:
                    timestamp = int(line[0])
                    return datetime.datetime.fromtimestamp(timestamp)
                except:
                    return datetime.datetime.now()

            lines.sort(key=cle_tri, reverse=False)
            for line in lines:
                try:
                    timestamp = int(line[0])
                    formatted_timestamp = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d|%H:%M:%S")
                    line[0] = formatted_timestamp
                except:
                    continue
        return lines

    def plaso_all(self):
        self.l2t()
        self.psort()

    def l2t(self):
        """
        To create a Timeline of all the files with Log2Timeline
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[CREATING] [LOG2TIMELINE]")
            tool_path = "log2timeline.py"
            my_cmd = ["{}".format(tool_path),
                      "--logfile", "{}".format(os.path.join(self.timelineDir, "l2t.log.gz")),
                      "--storage-file", "{}".format(os.path.join(self.timelineDir, "timeline.plaso")),
                      "{}".format(self.extracted_dir)]

            subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_1("[CREATING] [LOG2TIMELINE]")
        except:
            self.logger_run.print_info_failed_sub_1("[CREATING] [LOG2TIMELINE]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def psort(self):
        """
        To sort Log2timeline result file with plaso psort
        :return:
        """
        try:
            #  psort.py -w test.json -o json_line test_to_plaso.plaso
            self.logger_run.print_info_start_sub_1("[PSORT]")

            self.logger_run.print_info_start_sub_2("Sorting to json")
            tool_path = "psort.py"
            my_cmd = ["{}".format(tool_path),
                      "-o", "json_line",
                      "--logfile", "{}".format(os.path.join(self.timelineDir, "psortjson.log.gz")),
                      "-w",  "{}".format(os.path.join(self.timelineDir, "timeline.json")),
                      "{}".format(os.path.join(self.timelineDir, "timeline.plaso"))
                      ]
            subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_2("Sorting to json")

            self.logger_run.print_info_start_sub_2("Sorting to csv")
            my_cmd = ["{}".format(tool_path),
                      "--logfile", "{}".format(os.path.join(self.timelineDir, "psortcsv.log.gz")),
                      "-w",  "{}".format(os.path.join(self.timelineDir, "timeline.csv")),
                      "{}".format(os.path.join(self.timelineDir, "timeline.plaso"))
                      ]
            subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_2("Sorting to csv")
            self.logger_run.print_info_finished_sub_1("[PSORT]")
        except:
            self.logger_run.print_info_failed_sub_1("[PSORT]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def maximum_plaso_parser(self):
        """
        Launch Maximum plaso parser, a parser for json plaso timeline that convert a timeline to lot of differents
        artefacts files formated in human friendly format : DATE|TIME|ETC|ETC
        :return:
        """
        try:

            self.logger_run.print_info_start_sub_1("[Maximum Plaso Parser]")
            mp = MaximumPlasoParserJson.MaximumPlasoParserJson(
                self.parsed_dir,
                "csv",
                "|",
                self.case_name,
                None,
                None)

            mp.parse_timeline(os.path.join(self.timelineDir, "timeline.json"))
            self.logger_run.print_info_finished_sub_1("[Maximum Plaso Parser]")

        except:
            self.logger_run.print_info_failed_sub_1("[Maximum Plaso Parser]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_lnk(self):
        """
        To convert all LNK file to json and parse them to a human friendly format : DATE|TIME|ETC|ETC
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [LNK]")

            lnk_parser = LnkParser.LnkParser(self.result_parsed_dir)
            mngr = FileManager.FileManager()

            lnk_paterns = self.artefact_config.get("artefacts", {}).get("files", {}).get("lnk", "")
            for lnk_patern in lnk_paterns:
                lnk_files = mngr.recursive_file_search(self.extracted_dir, lnk_patern)

                for lnk_file in lnk_files:
                    try:
                        lnk_name = os.path.basename(lnk_file)
                        lnk_name_wo_ext = os.path.splitext(lnk_name)[0]

                        self.logger_run.print_info_start_sub_2("parsing {}".format(lnk_name_wo_ext))
                        lnk_parser.parse_lnk_to_json(lnk_file, self.lnkDir)
                        self.logger_run.print_info_finished_sub_2("parsing {}".format(lnk_name_wo_ext))

                    except:
                        self.logger_run.print_info_failed_sub_2("parsing {}".format(lnk_file))
                        self.logger_debug.print_error_failed(traceback.format_exc())

            self.logger_run.print_info_finished_sub_1("[PARSING] [LNK]")

        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [LNK]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def work(self):
        """
        To launch all parsers
        :return:
        """
        self.initialise_working_directories()

        self.logger_run.print_info_start("[ARCHIVES]")
        self.extract()
        self.logger_run.print_info_finished("[ARCHIVES]")

        self.logger_run.print_info_start("[FILES]")
        self.clean()
        self.move_txt_artefacts()
        self.parse_system_info()

        if self.parser_config.get("ParseProcess"):
            self.parse_process()
        if self.parser_config.get("ParseNetwork"):
            self.parse_network()
        if self.parser_config.get("parseLnk"):
            self.parse_lnk()
        self.logger_run.print_info_finished("[FILES]")

        if self.parser_config.get("ParsePrefetch"):
            self.parse_prefetch(False, True)

        if self.parser_config.get("EvtxToJson"):
            self.logger_run.print_info_start("[EVTX]")
            self.convert_evtx_to_json()
            if self.parser_config.get("ParseEvtx"):
                self.parse_evtx()
            self.logger_run.print_info_finished("[EVTX]")

        self.logger_run.print_info_start("[REGISTRY]")
        if self.parser_config.get("ParseSrum"):
            self.parse_srum()
        if self.parser_config.get("ParseSystemHivesRr"):
            self.parse_hives_rr()
        if self.parser_config.get("parseSystemHivesRegipy"):
            self.parse_system_hives_regipy()
        self.logger_run.print_info_finished("[REGISTRY]")

        if self.parser_config.get("parseMft"):
            self.logger_run.print_info_start("[MFT]")
            self.parse_mft()
            self.parse_usnjrnl()
            self.logger_run.print_info_finished("[MFT]")

        if self.parser_config.get('hayabusa'):
            self.logger_run.print_info_start("[HAYABUSA]")
            self.launch_hayabusa_subprocess()
            self.logger_run.print_info_finished("[HAYABUSA]")

        self.clean_duplicates(self.result_parsed_dir) # Need to be fixed

        if self.parser_config.get("plaso"):
            self.logger_run.print_info_start("[TIMELINE]")
            self.plaso_all()
            if self.parser_config.get("mpp"):
                self.maximum_plaso_parser()
            self.logger_run.print_info_finished("[TIMELINE]")


def parse_args():
    """
        Function to parse args
    """
    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse DFIR ORC Archive'))

    argument_parser.add_argument('-a', '--archive', action="store",
                                 required=True, dest="archive", default=False,
                                 help="path to a the orc archive")

    argument_parser.add_argument("-d", "--destination", action="store",
                                 required=True, dest="destination", default=False,
                                 help="folder where the result will be written")

    argument_parser.add_argument("-c", "--casename", action="store",
                                 required=True, dest="casename", default=False,
                                 help="name of the case")

    argument_parser.add_argument("-t", "--timeline", action="store_true",
                                 required=False, dest="isTimeline", default=False,
                                 help="Set to true to create a plaso timeline (might take a while")

    return argument_parser


if __name__ == '__main__':
    parser = parse_args()
    args = parser.parse_args()

    p = OrcPaser(args.archive, args.destination, args.casename)
    p.work(args.isTimeline)


# send to elk jq -c -r '. | {"index": {"_index": "caseName",}}, .' file.json | curl -XPOST "http://localhost:9200/_bulk?pretty" -H "Content-Type: application/json" --data-binary @-