#!/usr/bin/python3

import json


class ConfigManager:
    """
           Class to manage all interaction with the config file
    """

    def __init__(self) -> None:
        """
        The constructor for ConfigManager class.
        """
        pass

    @staticmethod
    def load_config(path_to_config_file):
        """
        Function to load the config from a json config file into a dict

        :param path_to_config_file: path to the config file to load
        :type path_to_config_file: str
        :return: dictionary containing the config info
        :rtype:  dict
        """

        try:
            with open(path_to_config_file, 'r') as config_file:
                config = json.load(config_file)
                print("config file : {} as been loaded".format(path_to_config_file))
            return config

        except Exception as ex:
            print("failed to read the config file : {}".format(path_to_config_file))

    @staticmethod
    def write_config(config, path_to_config_file):
        """
        Function to write to a config file, will overwrite it
        :param config: config to write as json
        :type config: dict
        :param path_to_config_file: path to the config file to write to
        :type path_to_config_file: str
        :return:
        :rtype:
        """
        try:
            with open(path_to_config_file, "w") as config_file:
                json.dump(config, config_file)

        except Exception as ex:
            print("failed to write to the config file : {}".format(path_to_config_file))


