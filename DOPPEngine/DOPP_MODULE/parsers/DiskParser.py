#!/usr/bin/python3
import os
import traceback
import argparse

class DiskParser:
    """
    Class to parse Disk info related artefacts
    """

    def __init__(self, output_directory="") -> None:
        """
        The constructor for DiskParser class.
        :param output_directory: str Full path to the directory where the files will be written
        """
        self.separator = "|"
        self.dir_out = output_directory

        self.usn_header = ["Date", "Time", "FileName", "Reason", "FilePath"]
        self.mft_header = ["CreationDate", "ModificationDate", "AccessDate", "EntryDate", "FilePath"]
        self.mft_result_file = ""
        self.usnjrnl_result_file = ""

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

    def parse_usnjrnl(self, file_path):
        """
        Parse USNJRNL csv file provided by DFIR ORC
        :param file_path: str: full path of the USN csv file
        :return:
        """

        self.usnjrnl_result_file = self.initialise_result_file_csv(self.usn_header, "usnjrnl_parsed")
        try:
            res = ""
            with open(file_path, 'r') as usnjrnl:
                for line in usnjrnl.readlines()[1:]:
                    l_line = line.split(",")
                    date, time = l_line[4].split(" ")
                    file_name = l_line[5]
                    file_path = l_line[6]
                    reason = l_line[8]

                    res = "{}{}{}{}{}{}{}{}{}".format(date,
                                                      self.separator, time,
                                                      self.separator, reason,
                                                      self.separator, file_name,
                                                      self.separator, file_path)
                    self.usnjrnl_result_file.write(res)
                    self.usnjrnl_result_file.write("\n")
        except Exception:
            print(traceback.format_exc())

    def parse_mft(self, file_path):
        """
        Parse MFT csv file provided by the tool analyzemft
        :param file_path:  str: ull path of the mft csv file
        :return:
        """

        self.mft_result_file = self.initialise_result_file_csv(self.mft_header, "mft_parsed")
        try:
            res = ""
            with open(file_path, 'r') as mft:
                for line in mft.readlines()[1:]:
                    if line and not "Corrupt" in line:
                        try:
                            l_line = line.split(",")
                            file_name = l_line[7].replace('"', "")
                            std_date_creation = l_line[8].split(".")[0].replace('"', "")
                            std_date_modification = l_line[9].split(".")[0].replace('"', "")
                            std_date_access = l_line[10].split(".")[0].replace('"', "")
                            std_date_entry = l_line[11].split(".")[0].replace('"', "")
                            res = "C:{}{} M:{}{} A:{}{} E:{}{}{}".format(
                                std_date_creation,
                                self.separator, std_date_modification,
                                self.separator, std_date_access,
                                self.separator, std_date_entry,
                                self.separator, file_name
                            )
                            self.mft_result_file.write(res)
                            self.mft_result_file.write("\n")
                        except:
                            continue
        except Exception:
            print(traceback.format_exc())

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Parse MFT and USNjrl cvs file to straight forward human readable files'))

    argument_parser.add_argument('-i', '--input', action="store",
                                 required=False, dest="input_file", default=False,
                                 help="path to the input file")

    argument_parser.add_argument('-u', '--usnjrnl', action="store",
                                 required=False, dest="usnjrnl", default=False,
                                 help="path to the usnjrnl file")

    argument_parser.add_argument('-m', '--mft', action="store",
                                 required=False, dest="mft", default=False,
                                 help="path to the mft file")


    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    return argument_parser


if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    parser = DiskParser(args.output_dir)
    if args.usnjrnl:
        parser.parse_usnjrnl(args.usnjrnl)
    if args.mft:
        parser.parse_mft(args.mft)


"""
MFT HEADER

"Record Number" 0
"Good" 1
"Active" 2
"Record type" 3
"Sequence Number" 4
"Parent File Rec. #" 5
"Parent File Rec. Seq. #" 6

"Filename #1" 7
"Std Info Creation date" 8
"Std Info Modification date" 9
"Std Info Access date" 10
"Std Info Entry date" 11

"FN Info Creation date" 12
"FN Info Modification date" 13
"FN Info Access date" 14
"FN Info Entry date" 15

"Object ID"
"Birth Volume ID"
"Birth Object ID"
"Birth Domain ID"

"Filename #2"
"FN Info Creation date"
"FN Info Modify date"
"FN Info Access date"
"FN Info Entry date"

"Filename #3"
"FN Info Creation date"
"FN Info Modify date"
"FN Info Access date"
"FN Info Entry date"

"Filename #4"
"FN Info Creation date"
"FN Info Modify date"
"FN Info Access date"
"FN Info Entry date"

"Standard Information"
"Attribute List"
"Filename"
"Object ID"
"Volume Name"
"Volume Info"
"Data"
"Index Root"
"Index Allocation"
"Bitmap"
"Reparse Point"
"EA Information"
"EA"
"Property Set"
"Logged Utility Stream"
"Log/Notes"
"STF FN Shift"
"uSec Zero"
"ADS"
"Possible Copy"
"Possible Volume Move"

"""