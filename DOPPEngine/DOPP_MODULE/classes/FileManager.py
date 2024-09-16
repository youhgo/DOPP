import shutil
import re
import os
import traceback
import pathlib


class FileManager:
    """
       Class to manage files
       Attributes :
       """

    def __init__(self, config="") -> None:
        """
        The constructor for FileManager class.
        Parameters:
        """
        if config:
            self.config = config

    def clean_filename(self, path_to_file):
        try:
            l_file_to_preserve = ["USNInfo", "NTFSInfo"]
            if os.path.exists(path_to_file):
                root, filename = os.path.split(path_to_file)
                if ".data" in filename or "_data" in filename:
                    for f in l_file_to_preserve:
                        if f in filename:
                            return
                    filename_wo_tail1 = re.sub(r'_\{.*\}.data$', '', filename)
                    filename_wo_tail2 = re.sub(r'\_data$', '', filename_wo_tail1)
                    filename_wo_head = re.sub(r'^(([a-zA-Z]|\d){0,30}_){0,3}', '', filename_wo_tail2)
                    final_name = os.path.join(root, filename_wo_head)
                    os.rename(path_to_file, final_name)
        except:
            print(traceback.format_exc())

    def rename_nested_folder(self, base_dir):
        try:
            for roots, dirs, files in os.walk(base_dir):
                for fileName in files:
                    file = os.path.join(roots, fileName)
                    self.clean_filename(file)
        except:
            print(traceback.format_exc())

    def find_files_n_recursive(self, path_in, ext):
        p = pathlib.Path(path_in).glob(ext)
        return p

    def find_files_n_recursive_regex(self, path_in, regu_exp):
        res = []
        for f in os.listdir(path_in):
            if re.search(regu_exp, f):
                res.append(os.path.join(path_in, f))
        return res

    def find_files_recursive(self, path_in, ext):
        def_file_lift = []
        p = pathlib.Path(path_in).rglob(ext)
        for item in p:
            if item.is_file():
                def_file_lift.append(item)
        return def_file_lift

    def list_files_recursive(self, folder_path):
        l_file = []
        path_folder = pathlib.Path(folder_path)
        for item in path_folder.rglob('*'):
            if item.is_file():
                l_file.append(item)
        return l_file

    def delet_specific_files(self, file_name, folder_name):
        pass

    def move_file_to_dest(self, file, new_dest):
        if os.path.isfile(file):
            end_path = os.path.join(new_dest, os.path.basename(file))
            shutil.move(file, end_path)

    def copy_file_to_dest(self, file, new_dest):
        if os.path.isfile(file):
            end_path = os.path.join(new_dest, os.path.basename(file))
            shutil.copy(file, end_path)

    def copy_folder_to_dest(self, folder, new_dest):
        if os.path.isdir(folder):
            end_path = os.path.join(new_dest, os.path.basename(folder))
            shutil.copytree(folder, end_path)

    def search_and_move_multiple_file_to_dest_recurs(self, dir_to_search, pattern, new_dest):
        for file in self.find_files_recursive(dir_to_search, pattern):
            self.move_file_to_dest(file, new_dest)

    def search_and_move_multiple_file_to_dest_n_recurs(self, dir_to_search, pattern, new_dest):
        for file in self.find_files_n_recursive(dir_to_search, pattern):
            self.move_file_to_dest(file, new_dest)

    def search_and_copy_multiple_file_to_dest_recurs(self, dir_to_search, pattern, new_dest):
        for file in self.find_files_recursive(dir_to_search, pattern):
            self.copy_file_to_dest(file, new_dest)

    def search_and_copy_multiple_file_to_dest_n_recurs(self, dir_to_search, pattern, new_dest):

        for file in self.find_files_n_recursive(dir_to_search, pattern):
            self.copy_file_to_dest(file, new_dest)

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

    def search_and_copy_recurs(self,dir_to_search, destination, reg_ex):
        l_file = self.recursive_file_search(dir_to_search, reg_ex)
        for file in l_file:
            self.copy_file_to_dest(file, destination)

