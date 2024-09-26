import json
import sys
import os
import traceback
from celery import Celery
from flask import jsonify
from DOPP_MODULE.OrcParser import OrcPaser

SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379'),
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379')
celery = Celery('tasks', broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)



@celery.task(queue='parse')
def parse_archive(content, file_name):
    """
     Celery Tasks function "parse_archive" which will parse an archive generated by DFIR-ORC.

    :param content: parameters of the request
    :type content: str
    :param file_name: file name of the file wich was uploaded
    :type file_name: str
    :return: message telling the result of the analysis
    :rtype: str
    """

    try:
        main_id = parse_archive.request.id
        archive_path = os.path.join(DEPOT_FOLDER_PATH, file_name)
        case_name = content.get("caseName")
        o_parser = OrcPaser(archive_path, WORKING_FOLDER_PATH, case_name, main_id, content.get('parser_config', None),
                            content.get('artefact_config', None))
        o_parser.work()

        return {"taskId": "{}".format(main_id), "WokerStatus": "finished"}

    except Exception as ex:
        sys.stderr.write("\nerror : {}\n".format(traceback.format_exc()))
        return {"taskId": "{}".format(main_id), "WokerStatus": "Failled"}

