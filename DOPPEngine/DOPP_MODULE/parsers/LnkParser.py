#!/usr/bin/python3
import os
import traceback
import argparse
import LnkParse3
import json


class LnkParser:
    """
       Class to parse lnk files
    """

    def __init__(self, output_directory="") -> None:
        """
        The constructor for lnkParser Class
        Parameters:

        """
        self.separator = "|"
        self.dir_out = output_directory

        self.lnk_header = ["CreationTime", "AccessTime", "ModifiedTime", "Target/Path/Description", "lnkName"]
        self.lnk_result_file = self.initialise_result_file_csv(self.lnk_header, "lnk_parsed")

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

    def parse_lnk_to_json(self, file_path, dir_out):
        """
        Main function to convert lnk files to json files
        :param file_path: str : path to the lnk file
        :param dir_out:  str : path to the result folder
        :return:
        """
        lnk_name = os.path.basename(file_path)
        path_out_json = os.path.join(dir_out, "{}.json".format(lnk_name))
        try:
            res = ""
            with open(file_path, 'rb') as file_in:
                lnk = LnkParse3.lnk_file(file_in)
                res = lnk.get_json()
            if res:
                self.parse_lnk_json_to_csv(res, lnk_name)
                with open(path_out_json, "a") as outfile:
                    json.dump(res, outfile, default=str)

        except Exception:
            print("couldn't parse {}".format(file_path))
            print(traceback.format_exc())

    def parse_all_lnk_to_json(self, input_dir, dir_out):
        for item in os.listdir(input_dir):
            if item.endswith(".lnk"):
                self.parse_lnk_to_json(os.path.join(input_dir, item), dir_out)

    def parse_lnk_json_to_csv(self, lnk_as_json, file_name):
        """
        To parse json file to human-readble file |DATE|TIME|ETC|ETC
        :param lnk_as_json: dict containing the lnk info
        :return:
        """
        creation_time = lnk_as_json.get("header",{}).get("creation_time","-")
        accessed_time = lnk_as_json.get("header",{}).get("accessed_time","-")
        modified_time = lnk_as_json.get("header",{}).get("modified_time","-")

        local_path = lnk_as_json.get("link_info",{}).get("local_base_path","")
        if not local_path:
             local_path = lnk_as_json.get("extra",{}).get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK",{}).get("target_ansi","")
        if not local_path:
            local_path = lnk_as_json.get("data",{}).get("description","-")

        res = "{}{}{}{}{}{}{}{}{}".format(creation_time,
                                          self.separator, accessed_time,
                                          self.separator, modified_time,
                                          self.separator, local_path,
                                          self.separator, file_name)
        self.lnk_result_file.write(res)
        self.lnk_result_file.write("\n")




def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Parser for json formated lnk files'))

    argument_parser.add_argument('-i', '--input', action="store",
                                 required=False, dest="input_file", default=False,
                                 help="path to the input file")

    argument_parser.add_argument('-f', '--folder', action="store",
                                 required=False, dest="input_folder", default=False,
                                 help="path to the input folder")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    return argument_parser


if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    parser = LnkParser(args.output_dir)
    if args.input_folder:
        parser.parse_all_lnk_to_json(args.input_folder, args.output_dir)
    if args.input_file:
        parser.parse_lnk_to_json(args.input_file, args.output_dir)
