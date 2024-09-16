import argparse
import datetime
import subprocess
import sys
import os
import traceback
import re

from pathlib import Path
from .classes import FileManager, Extractor, LoggerManager
from .parsers import (EventParser, ProcessParser, PrefetchParser, NetWorkParser, RegistryParser, LnkParser,
                      MaximumPlasoParserJson, DiskParser)

# TODO: Replay all hives transactions
# TODO: Parse browser History
# TODO: CREATE JSON OUTPUT FOR EVERY PARSER
# TODO: PARSE AMCACHE
# TODO: NOT RESTRAIN TO ORC
# TODO: Create a config file with all artefact filenames to parse
# TODO: AD_computer.csv to parse
# TODO: SEARCH PROPERLY FOR ARTEFACT
# TODO: CHECK PROPERLY BEFORE PARSING RESULTS TO HUMAN READABLE

class OrcPaser:
    """
    Main class to launch all tools
    """

    def __init__(self, path_to_orc, path_to_work_dir, case_name, master_id="", parser_config=None, artefact_config=None) -> None:
        """
        Constructor for Orc Parser class
        :param path_to_orc: str : path to archive
        :param path_to_work_dir: str : path to working directory (where all processed file will be written)
        :param case_name: str: name of the case
        :param master_id: celery process id
        :param config: json/dict parsers config
        """
        self.tool_path = os.environ.get("TOOL_PATH", "python-docker/DOPP_MODULE/outils")
        self.evtx_dump_path_old = os.path.join(self.tool_path, "evtx_dump")
        self.evtx_dump_path = os.path.join(self.tool_path, "evtxdump")
        self.ese_analyst_path = os.path.join(self.tool_path, "ese-analyst/ese2csv.py")
        self.ese_analyst_plugin_path = os.path.join(self.tool_path, "ese-analyst/srudb_plugin.py")

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

        self.eventsDir = os.path.join(self.parsed_dir, "events")
        self.eventsJsonDir = os.path.join(self.eventsDir, "events-json")
        self.eventsParsedDir = os.path.join(self.eventsDir, "events-parsed")

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

    def initialise_working_directories(self):
        """
            To create directories where the results will be written
        """
        try:
            os.makedirs(self.work_dir, exist_ok=True)
            os.makedirs(self.orc_folder, exist_ok=True)
            os.makedirs(self.extracted_dir, exist_ok=True)
            os.makedirs(self.parsed_dir, exist_ok=True)

            os.makedirs(self.eventsDir, exist_ok=True)
            os.makedirs(self.eventsJsonDir, exist_ok=True)
            os.makedirs(self.eventsParsedDir, exist_ok=True)

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

            self.logger_run = LoggerManager.LoggerManager("running", self.running_log_file_path, "INFO")
            self.logger_debug = LoggerManager.LoggerManager("debug", self.debug_log_file_path, "DEBUG")

        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

    def extract(self):
        """
         to extract orc archives
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[EXTRACTING] archives")
            extr = Extractor.OrcExtractor()
            extr.extract_orc_archive(self.path_to_orc, self.extracted_dir)
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

    def move_debug(self):
        """
        to move file to debug folder
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[MOVING] debugs files")

            l_to_move = ["Statistics.json", "Statistics_*.json", "*_config.xml", "GetThis*", "config.xml", "Config.xml",
                         "FastFind_result.xml"]
            mngr = FileManager.FileManager()
            for f_patern in l_to_move:
                mngr.search_and_move_multiple_file_to_dest_recurs(self.extracted_dir, f_patern, self.debugDir)
            mngr.search_and_move_multiple_file_to_dest_n_recurs(self.extracted_dir, "*.log", self.debugDir)

            self.logger_run.print_info_finished_sub_1("[MOVING] debugs files")
        except:
            self.logger_run.print_info_failed_sub_1("[MOVING] debugs files")
            self.logger_debug.print_error_failed(traceback.format_exc())
        
    def move_no_parse(self):
        """
        to move file that don't need to be parsed
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[MOVING] already parsed files")

            mngr = FileManager.FileManager()
            l_to_move = ["NTFSInfo_*", "Enumlocs.txt", "USNInfo_*", "VSS_list.csv"]
            for f_patern in l_to_move:
                mngr.search_and_copy_multiple_file_to_dest_recurs(self.extracted_dir, f_patern, self.mftDir)

            l_to_move = ["autoruns.csv", "Listdlls.txt", "processes1.csv", "processes2.csv", "handle.txt",
                         "EventConsumer.txt"]
            for f_patern in l_to_move:
                mngr.search_and_copy_multiple_file_to_dest_recurs(self.extracted_dir, f_patern, self.processDir)

            l_to_move = ["Tcpvcon.txt", "netstat.txt", "dns_cache.txt", "BITS_jobs.txt", "routes.txt",
                         "arp_cache.txt"]
            for f_patern in l_to_move:
                mngr.search_and_copy_multiple_file_to_dest_recurs(self.extracted_dir, f_patern, self.netWorkDir)

            l_to_move = ["Systeminfo.csv"]
            for f_patern in l_to_move:
                mngr.search_and_copy_multiple_file_to_dest_recurs(self.extracted_dir, f_patern, self.parsed_dir)

            ext_text_log_dir = os.path.join(self.extracted_dir, "TextLogs")
            l_to_move = ["*ConsoleHost_history.txt", "*ModuleAnalysisCache"]
            for f_patern in l_to_move:
                mngr.search_and_copy_multiple_file_to_dest_recurs(ext_text_log_dir, f_patern, self.powershellDir)

            l_to_move = ["*networks", "*hosts", "*lmhosts.sam", "*protocol", "*services"]
            for f_patern in l_to_move:
                mngr.search_and_copy_multiple_file_to_dest_recurs(ext_text_log_dir, f_patern, self.netWorkDir)

            ext_diver_dir_path = os.path.join(ext_text_log_dir, "divers")
            mngr.copy_folder_to_dest(ext_diver_dir_path, self.txtLogDir)
            ext_hives_log_dir_path = os.path.join(ext_text_log_dir, "hives_log")
            mngr.copy_folder_to_dest(ext_hives_log_dir_path, self.txtLogDir)

            self.logger_run.print_info_finished_sub_1("[MOVING] already parsed files")

        except:
            self.logger_run.print_info_failed_sub_1("[MOVING] already parsed files")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def convert_evtx_to_json(self):
        """
        to Launch evtdump for converting evtx file to json files
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[CONVERTING] [EVTX] [JSON]")
            mngr = FileManager.FileManager()
            for evt in mngr.find_files_recursive(self.extracted_dir, "*.evtx"):
                try:
                    evt_name = os.path.basename(evt)
                    evt_name_wo_ext = os.path.splitext(evt_name)[0]
                    evt_json_name = evt_name_wo_ext + ".json"
                    self.logger_run.print_info_start_sub_2("Converting {} to json".format(evt_name_wo_ext))
                    out_file = os.path.join(self.eventsJsonDir, evt_json_name)
                    my_cmd = ["{}".format(self.evtx_dump_path), "{}".format(evt)]
                    with open(out_file, "w") as outfile:
                        subprocess.run(my_cmd, stdout=outfile)
                    self.logger_run.print_info_finished_sub_2("Converting {} to json".format(evt_name_wo_ext))
                except:
                    self.logger_run.print_info_failed_sub_2("Converting {} to json".format(evt_name))

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
            evtparser = EventParser.EventParser(self.eventsJsonDir, self.result_parsed_dir)
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

            proc_parser = ProcessParser.ProcessParser(self.result_parsed_dir)

            self.logger_run.print_info_start_sub_2("[PARSING] [SYSITERNALS_AUTORUNS]")
            search = [f for f in os.listdir(self.extracted_dir) if
                      re.search(r'autoruns\.csv$', f)]
            if search:
                relative_file_path = Path(os.path.join(self.extracted_dir, search[0]))
                absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
                proc_parser.parse_autoruns_sysinternals(absolute_file_path)
            self.logger_run.print_info_finished_sub_2("[PARSING] [SYSITERNALS_AUTORUNS]")

            self.logger_run.print_info_start_sub_2("[PARSING] [PROCESSES1]")
            search = [f for f in os.listdir(self.extracted_dir) if
                      re.search(r'processes1\.csv$', f)]
            if search:
                relative_file_path = Path(os.path.join(self.extracted_dir, search[0]))
                absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
                proc_parser.parse_process1(absolute_file_path)
            self.logger_run.print_info_finished_sub_2("[PARSING] [PROCESSES1]")

            self.logger_run.print_info_start_sub_2("[PARSING] [PROCESSES2]")
            search = [f for f in os.listdir(self.extracted_dir) if
                      re.search(r'processes2\.csv$', f)]
            if search:
                relative_file_path = Path(os.path.join(self.extracted_dir, search[0]))
                absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
                proc_parser.parse_process2(absolute_file_path)
            self.logger_run.print_info_finished_sub_2("[PARSING] [PROCESSES2]")

            self.logger_run.print_info_start_sub_2("[PARSING] [PROCESSES_TIMELINE]")
            search = [f for f in os.listdir(self.extracted_dir) if
                      re.search(r'(GetSamples_timeline\.csv|Process_timeline\.csv)', f)]
            if search:
                relative_file_path = Path(os.path.join(self.extracted_dir, search[0]))
                absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
                proc_parser.parse_process_timeline(absolute_file_path)
            self.logger_run.print_info_finished_sub_2("[PARSING] [PROCESSES_TIMELINE]")

            self.logger_run.print_info_start_sub_2("[PARSING] [PROCESSES_INFO]")
            search = [f for f in os.listdir(self.extracted_dir) if
                      re.search(r'(GetSamples_sampleinfo\.csv|Process_sampleinfo\.csv)', f)]
            if search:
                relative_file_path = Path(os.path.join(self.extracted_dir, search[0]))
                absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
                proc_parser.parse_process_infos(absolute_file_path)
            self.logger_run.print_info_finished_sub_2("[PARSING] [PROCESSES_INFO]")

            self.logger_run.print_info_start_sub_2("[PARSING] [PROCESS_AUTORUNS]")
            search = [f for f in os.listdir(self.extracted_dir) if
                      re.search(r'(GetSamples_autoruns\.xml|Process_Autoruns\.xml)', f)]
            if search:
                relative_file_path = Path(os.path.join(self.extracted_dir, search[0]))
                absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
                proc_parser.parse_process_autoruns(absolute_file_path)
            self.logger_run.print_info_finished_sub_2("[PARSING] [PROCESS_AUTORUNS]")

            self.logger_run.print_info_finished_sub_1("[PARSING] [PROCESSES]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [PROCESSES]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_network(self):
        """
        To parse network results files to the human readable format Date|Time|ID|ETC
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
        To parse prefetch files to the human readable format Date|Time|ID|ETC
        :param is_volume: bool
        :param is_json: bool
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [PREFETCH]")
            pf_parser = PrefetchParser.PrefetchParser()
            pf_dir = Path(os.path.join(self.extracted_dir, "Artefacts/Prefetch")).absolute()
            output = pf_parser.parse_dir(pf_dir, is_volume)
            pf_parser.outputResults(output, os.path.join(self.prefetchDir, "prefetch-parsed.csv"), is_json, is_volume)
            self.logger_run.print_info_finished_sub_1("[PARSING] [PREFETCH]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [PREFETCH]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    #TODO : Check for multiple files
    def parse_srum(self):
        """
        To parse srum files to the human readable format Date|Time|ID|ETC
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [SRUM]")

            srum_dir = Path(os.path.join(self.extracted_dir, "Artefacts/SRUM/")).absolute()

            search = [f for f in os.listdir(srum_dir) if
                      re.search(r'SRUDB\.dat$', f)]
            if search:
                relative_file_path = Path(os.path.join(srum_dir, search[0]))
                absolute_file_path = relative_file_path.absolute()  # absolute is a Path object

                my_cmd = ["python3", "{}".format(self.ese_analyst_path), "--plugin",
                          "{}".format(self.ese_analyst_plugin_path),
                          "-o", "{}".format(self.srumDir), "{}".format(absolute_file_path)]
            # need to find a way to use this as a library

            subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_1("[PARSING] [SRUM]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [SRUM]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_system_hives_rr(self):
        """
        To parse systems hives files with RegRipper
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [SYTEM HIVE] [REGRIPPER]")
            l_hive_to_search = ["*SOFTWARE", "*SECURITY", "*SYSTEM", "*Amcache.hve", "*SAM"]
            mngr = FileManager.FileManager()
            for hive_name in l_hive_to_search:
                for hv in mngr.find_files_recursive(self.extracted_dir, hive_name):
                    hv_name = os.path.basename(hv)
                    self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))
                    out_file = os.path.join(self.hiveDirRR, hive_name.replace("*", "")+".txt")
                    my_cmd = ["rip.pl", "-r", "{}".format(hv), "-at", "-g"]
                    with open(out_file, "a") as outfile:
                        subprocess.run(my_cmd, stdout=outfile)
                    self.logger_run.print_info_finished_sub_2("parsing {}".format(hv_name))

            self.logger_run.print_info_finished_sub_1("[PARSING] [SYTEM HIVE] [REGRIPPER]")

        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [SYTEM HIVE] [REGRIPPER]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_system_hives_regipy(self):
        """
        To parse systems hives files with Regipy
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [SYTEM HIVE] [REGIPY]")
            reg_parser = RegistryParser.RegistryParser()
            l_hive_to_search = ["*SOFTWARE", "*SECURITY", "*SYSTEM", "*Amcache.hve"]
            mngr = FileManager.FileManager()
            for hive_name in l_hive_to_search:
                for hv in mngr.find_files_recursive(os.path.join(self.extracted_dir, "SystemHives"), hive_name):
                    hv_name = os.path.basename(hv)
                    self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))
                    if "SYSTEM" in hv_name.upper():
                        reg_parser.parse_system(hv, self.hiveDirRegipy)
                    if "SECURITY" in hv_name.upper():
                        reg_parser.parse_security(hv, self.hiveDirRegipy)
                    if "SOFTWARE" in hv_name.upper():
                        self.logger_run.print_info_failed_sub_2("Regipy can't handle SOFTWARE Hive")
                        #reg_parser.parse_security(hv, self.hiveDirRegipy)
                    if "AMCACHE" in hv_name.upper():
                        reg_parser.parse_amcache(hv, self.hiveDirRegipy)
                    self.logger_run.print_info_finished_sub_2("parsing {}".format(hv_name))

            self.logger_run.print_info_finished_sub_1("[PARSING] [SYTEM HIVE] [REGIPY]")

        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [SYTEM HIVE] [REGIPY]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_user_hives_rr(self):
        """
        To parse users hives files with RegRipper
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [USER HIVE] [REGRIPPER]")
            l_hive_to_search = ["*NTUSER.DAT"]
            mngr = FileManager.FileManager()
            for hive_name in l_hive_to_search:
                for hv in mngr.find_files_recursive(self.extracted_dir, hive_name):
                    hv_name = os.path.basename(hv)
                    self.logger_run.print_info_start_sub_2("parsing {}".format(hv_name))
                    out_file = os.path.join(self.hiveDirRR,  hv_name.replace("*", "")+".txt")
                    my_cmd = ["rip.pl", "-r", "{}".format(hv), "-at", "-g"]
                    with open(out_file, "a") as outfile:
                        subprocess.run(my_cmd, stdout=outfile)
                    self.logger_run.print_info_finished_sub_2("parsing {}".format(hv_name))

            self.logger_run.print_info_finished_sub_1("[PARSING] [USER HIVE] [REGRIPPER]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [USER HIVE] [REGRIPPER]")
            self.logger_debug.print_error_failed(traceback.format_exc())

    def parse_mft(self):
        """
        To parse mft file with analyse mft and parse it to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """
        try:
            self.logger_run.print_info_start_sub_1("[PARSING] [MFT]")
            mft_dir = Path(os.path.join(self.extracted_dir, "MFT/")).absolute()  # absolute is a Path object
            mngr = FileManager.FileManager()
            l_mft = list(mngr.find_files_recursive(mft_dir, "*MFT"))
            mft_result_file = os.path.join(self.mftDir, "mft.csv")
            for i in l_mft:
                my_cmd = ["analyze_mft", "-f", "{}".format(i),
                          "-o", "{}".format(mft_result_file)]
                subprocess.run(my_cmd)
            mft_parser = DiskParser.DiskParser(self.result_parsed_dir)
            mft_parser.parse_mft(mft_result_file)
            self.logger_run.print_info_finished_sub_1("[PARSING] [MFT]")
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
            l_usn = list(mngr.find_files_n_recursive_regex(self.mftDir, r'USNInfo'))
            for i in l_usn:
                usn_parser = DiskParser.DiskParser(self.result_parsed_dir)
                usn_parser.parse_usnjrnl(i)
            self.logger_run.print_info_finished_sub_1("[PARSING] [USNJRNL]")
        except:
            self.logger_run.print_info_failed_sub_1("[PARSING] [USNJRNL]")
            self.logger_debug.print_error_failed(traceback.format_exc())


    def plaso_all(self):
        self.l2t()
        self.psort()

    def plaso_all_legacy(self):
        try:
            self.logger_run.print_info_start_sub_1("[PLASO]")
            tool_path = "psteal.py"
            my_cmd = ["{}".format(tool_path), "--source", "{}".format(self.extracted_dir),
                      "-w",  "{}".format(os.path.join(self.timelineDir, "timeline.json")), "-o", "json_line"]
            subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_1("[PLASO]")
        except:
            self.logger_run.print_info_failed_sub_1("[PLASO]")
            self.logger_debug.print_error_failed(traceback.format_exc())

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

    def maximum_plaso_parser_subprocess(self):
        try:
            #  python3 MaximumPlasoParserJson.py
            #  -c "geelong"
            #  --type "csv"
            #  -o /home/hro/Documents/cyber/working_zone/testMP
            #  -t /home/hro/Documents/cyber/working_zone/samples_tl/full_timeline_graal.json
            #  -m workstation_graal

            self.logger_run.print_info_start_sub_1("[Maximum Plaso Parser]")
            tool_path = "python3 /parsers/MaximumPlasoParserJson.py"
            my_cmd = ["{}".format(tool_path),
                      "-c", "{}".format(self.case_name),
                      "--type", "csv",
                      "-t",  "{}".format(os.path.join(self.timelineDir, "timeline.json")),
                      "-o", "{}".format(self.extracted_dir)
                      ]
            subprocess.run(my_cmd)
            self.logger_run.print_info_finished_sub_1("[Maximum Plaso Parser]")

        except:
            self.logger_run.print_info_failed_sub_1("[Maximum Plaso Parser]")
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
            reg_lnk = re.compile(r'.*\.lnk$')
            lnk_parser = LnkParser.LnkParser(self.result_parsed_dir)
            mngr = FileManager.FileManager()
            for lnk_file in mngr.find_files_n_recursive_regex(os.path.join(self.extracted_dir, "Artefacts/lnk"), reg_lnk):
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
        self.move_debug()
        self.move_no_parse()
        if self.parser_config.get("ParseProcess"):
            self.parse_process()
        if self.parser_config.get("ParseNetwork"):
            self.parse_network()
        if self.parser_config.get("ParsePrefetch"):
            self.parse_prefetch(False, True)
        if self.parser_config.get("parseLnk"):
            self.parse_lnk()
        self.logger_run.print_info_finished("[FILES]")

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
            self.parse_system_hives_rr()
        if self.parser_config.get("parseUserHivesRr"):
            self.parse_user_hives_rr()
        if self.parser_config.get("parseSystemHivesRegipy"):
            self.parse_system_hives_regipy()
        self.logger_run.print_info_finished("[REGISTRY]")

        if self.parser_config.get("parseMft"):
            self.logger_run.print_info_start("[MFT]")
            self.parse_mft()
            self.parse_usnjrnl()
            self.logger_run.print_info_finished("[MFT]")

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