import py7zr
import re
import os
import traceback


class OrcExtractor:
    """
       Class to Extract archives
    """

    def __init__(self) -> None:
        """
        The constructor for OrcExtractor class.
        """
        pass

    def extract(self, zipped_file, to_folder, password='infected'):
        try:
            print("extracting {} to {}".format(zipped_file, to_folder))
            with py7zr.SevenZipFile(zipped_file, mode='r', password=password) as z:
                z.extractall(path=to_folder)
        except FileNotFoundError:
                pass
        except:
            print(traceback.format_exc())

    def extract_and_create_dir_name(self, zipped_file):
        """ Unzip a zip file
        """
        try:
            root, filename = os.path.split(zipped_file)  # /blabla/ - orc1.7z
            filename_wo_ext = filename.replace(".7z", "")  # /blabla/orc1
            new_path_out = os.path.join(root, filename_wo_ext)  # /blabla/orc1
            os.makedirs(new_path_out, exist_ok=True)
            self.extract(zipped_file, new_path_out)
        except FileNotFoundError:
            pass
        except:
            print(traceback.format_exc())

    def extract_nested_zip(self, zipped_file, to_folder):
        """ Unzip a zip file and its contents, including nested zip files
            Delete the zip file(s) after extraction
        """
        try:
            self.extract_and_create_dir_name(zipped_file)
            os.remove(zipped_file)
            for root, dirs, files in os.walk(to_folder):
                for filename in files:
                    if re.search(r'\.7z$', filename):
                        file_spec = os.path.join(root, filename)
                        self.extract_nested_zip(file_spec, root)
        except FileNotFoundError:
            pass
        except:
            print(traceback.format_exc())

    def extract_orc_archive(self, zipped_file, to_folder):
        """ Extract a zip file including nested zip files
            Delete the zip file(s) after extraction
        """
        try:
            self.extract(zipped_file, to_folder)
            for root, dirs, files in os.walk(to_folder):
                for filename in files:
                    if re.search(r'\.7z$', filename):
                        file_spec = os.path.join(root, filename)
                        self.extract_nested_zip(file_spec, root)
        except Exception as ex:
            print(traceback.format_exc())
