import json
import os
import sys
import time
import traceback

from flask import Blueprint, request, Response, url_for, jsonify
from worker import celery
from random import randint


parse_api = Blueprint('parse_api', __name__)
DOPP_API = "https://DOPP.localhost"
SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")


@parse_api.route('/parse_archive', methods=['POST'])
def parse_archive():
    """
    API function to call Tasks function "parse_archive" which will parse an archive generated by DFIR-ORC.

    :return: Message for the client
    :rtype: str
    """
    try:
        rand = randint(1000, 5000)
        file = request.files['file']
        file_name = file.filename + "__{}".format(rand)
        file_path = os.path.join(DEPOT_FOLDER_PATH, file_name)
        file.save(file_path)
        content = json.loads(request.form['json'])
        task = celery.send_task("tasks.parse_archive", args=[content, file_name], kwargs={}, queue="parse")
        status_uri = url_for('dopp_api.check_task', task_id=task.id)
        debug_uri = url_for('dopp_api.check_logs_debug', task_id=task.id)
        run_uri = url_for('dopp_api.check_logs_run', task_id=task.id)
        response = {
            "message": "your parsing request has been send to queue",
            "taskId": "{}".format(task.id),
            "statusUrl": "{}{}".format(DOPP_API, status_uri),
            "debugLogUrl": "{}{}".format(DOPP_API, debug_uri),
            "runLogUrl": "{}{}".format(DOPP_API, run_uri)
        }
        time.sleep(1)
        return jsonify(response), 200

    except Exception as ex:
        sys.stderr.write("\nerror : {}\n".format(traceback.format_exc()))
        return jsonify({"error": "Your request seems bad"})


def stop_tasks_by_queue_name(queue_name) -> Response:
    """
    api function to stop all task in a queue
    :return: id of the last taked killed
    :rtype: int
    """
    task_list = get_worker_tasks(queue_name)
    l_task_killed = ""
    if task_list:
        l_task_killed = stop_worker_tasks(task_list)

    return l_task_killed


def get_worker_tasks(queue_name):
    """
    Function to get all the tasks assigned to a worker
    :param queue_name: name of the queue to search for
    :type queue_name: str
    :return: list of all tasks
    :rtype: list
    """
    all_nodes = celery.control.inspect()
    worker_name = get_worker_name_from_queue(all_nodes, queue_name)
    worker_tasks = all_nodes.active().get(worker_name, [])
    return worker_tasks


def stop_worker_tasks(task_list):
    """
    function to stop all tasks by id
    :param task_list: list containing all the id of the tasks to kill
    :type task_list: list
    :return: list of killed tasks
    :rtype: list
    """
    l_killed_tasks = []
    for task_info in task_list:
        task_id = task_info.get('id', "")
        if task_id:
            celery.control.revoke(task_id, terminate=True, signal='SIGKILL')
            l_killed_tasks.append(task_id)
    return l_killed_tasks


def get_worker_name_from_queue(all_nodes, queue_name):
    """
    Get the worker's id associated to a queue
    :param all_nodes: the celery/redis node concerned
    :type all_nodes: celery node
    :param queue_name: name of the queue to search
    :type queue_name: str
    :return: worker id
    :rtype: str
    """
    cache_worker_id = ""
    for k, v in all_nodes.active_queues().items():
        if v[0].get('name', '') == queue_name:
            cache_worker_id = k
    return cache_worker_id
