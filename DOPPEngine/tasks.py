import sys
import os
import traceback
from celery import Celery
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
    :type content: dict
    :param file_name: file name of the file which was uploaded
    :type file_name: str
    :return: message telling the result of the analysis
    :rtype: str
    """

    try:
        main_id = parse_archive.request.id
        archive_path = os.path.join(DEPOT_FOLDER_PATH, file_name)
        case_name = content.get("caseName", "")
        machine_name= get_machine_name(content, file_name)
        parser_config = content.get('parser_config', None)
        artefact_config = content.get('artefact_config', None)
        o_parser = OrcPaser(archive_path, WORKING_FOLDER_PATH, case_name, machine_name,
                            main_id, parser_config, artefact_config)
        o_parser.work()

        return {"taskId": "{}".format(main_id), "WokerStatus": "finished"}

    except Exception as ex:
        sys.stderr.write("\nerror : {}\n".format(traceback.format_exc()))
        return {"taskId": "{}".format(parse_archive.request.id), "WokerStatus": "Failled"}


def get_machine_name(content_data, archive_file_name):
    machine_name = ""
    if content_data.get("machineName", ""):
        machine_name = content_data.get("machineName")
    elif "DFIR-ORC_" in archive_file_name:
        machine_name = os.path.splitext(archive_file_name.replace("DFIR-ORC_", ""))[0]
    else:
        machine_name = os.path.splitext(archive_file_name)[0]
    return machine_name
