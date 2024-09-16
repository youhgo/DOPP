import sys
import traceback

from flask import Blueprint, Response, jsonify, render_template
from worker import celery
import celery.states as states
from datetime import datetime
import os
import json

dopp_api = Blueprint('dopp_api', __name__)
SHARED_FOLDER_PATH = "/python-docker/shared_files/"
DEPOT_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "depot")
WORKING_FOLDER_PATH = os.path.join(SHARED_FOLDER_PATH, "work")
LOG_FOLDER_PATH = os.path.join(WORKING_FOLDER_PATH, "execution_logs")


@dopp_api.route("/")
def index():
    """
    api function to welcom user and check if co is ok
    :return:
    :rtype:
    """
    """
    api function to check health
    :return: OK
    :rtype: json dict
    """
    dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    response = {
        "message": "Welcom to Dfir-Orc Parser Project",
        "status": "OK",
        "serveurTime": "{}".format(dt_string)
    }
    return jsonify(response)


@dopp_api.route("/index")
def gui_index():
    """
    api function to welcom user and check if co is ok
    :return:
    :rtype:
    """
    """
    api function to check health
    :return: OK
    :rtype: json dict
    """
    return render_template('index.html')

@dopp_api.route('/api/check/<string:task_id>')
def check_task(task_id: str) -> str:
    """
    API function to get the task status
    :param task_id:
    :type task_id:
    :return: task status
    :rtype: str
    """
    res = celery.AsyncResult(task_id)
    if res.state == states.PENDING:
        return jsonify(res.state)
    else:
        return jsonify(str(res.result))


@dopp_api.route('/api/debug_log/<string:task_id>')
def check_logs_debug(task_id: str) -> str:
    """
    API function to get the task status
    :param task_id:
    :type task_id:
    :return: task status
    :rtype: str
    """
    try:
        result_file = os.path.join(LOG_FOLDER_PATH, "{}_debug.log".format(task_id))
        with open(result_file) as f:
            return "'<br>'".join(f.readlines())

    except Exception as ex:
        sys.stderr.write(traceback.format_exc())
        return jsonify({"ERROR": "TASK NOT FOUND, plz verify id",
                        "TASKID": "{}".format(task_id)}), 404


@dopp_api.route('/api/running_log/<string:task_id>')
def check_logs_run(task_id: str) -> str:
    """
    API function to get the task status
    :param task_id:
    :type task_id:
    :return: task status
    :rtype: str
    """
    try:
        result_file = os.path.join(LOG_FOLDER_PATH, "{}_running.log".format(task_id))
        with open(result_file) as f:
            return "'<br>'".join(f.readlines())

    except Exception as ex:
        sys.stderr.write(traceback.format_exc())
        return jsonify({"ERROR": "TASK NOT FOUND, plz verify id",
                        "TASKID": "{}".format(task_id)}), 404


@dopp_api.route('/api/celery_worker_info')
def list_tasks() -> Response:
    """
    api function to check worker infos
    :return: OK
    :rtype: json dict
    """

    all_nodes = celery.control.inspect()

    response = {
        "active": all_nodes.active(),
        "allInfo": all_nodes.active_queues(),
    }
    return response


@dopp_api.route('/api/get_running_tasks')
def get_running_tasks():
    """
    Function to get active celery running tasks
    :return:
    :rtype:
    """
    return celery.control.inspect().active()


@dopp_api.route('/api/stop_analyze_tasks')
def stop_parsing_tasks() -> Response:
    """
    api function to stop tasks related to parsing module
    :return: json response
    :rtype: json dict
    """
    task_list = get_parser_tasks()
    l_task_killed = ""
    if task_list:
        l_task_killed = stop_task(task_list)

    all_nodes = celery.control.inspect()
    response = {
        "active": all_nodes.active(),
        "killedTasks": l_task_killed
    }
    return response


@dopp_api.route('/api/get_running_tasks_parse')
def get_parser_tasks():
    """
    api function to get tasks related to parser module
    :return: list of tasks id
    :rtype: list
    """
    all_nodes = celery.control.inspect()
    worker_parser_name = get_parser_worker_name(all_nodes)
    worker_parser_tasks = all_nodes.active().get(worker_parser_name, [])
    return worker_parser_tasks


def stop_task(task_list):
    """
    function to kill tasks by it's id

    :param task_list: list of tasks id that will been killed
    :type task_list: list
    :return: list of tasks id that have been killed
    :rtype: list
    """
    l_killed_tasks = []
    for task_info in task_list:
        task_id = task_info.get('id', "")
        if task_id:
            celery.control.revoke(task_id, terminate=True, signal='SIGKILL')
            l_killed_tasks.append(task_id)
    return l_killed_tasks


def get_parser_worker_name(all_nodes):
    """
    function to get the worker id that process the parsing tasks
    :param all_nodes: all celery node
    :type all_nodes: celecry node
    :return: cache worker id
    :rtype: int
    """
    cache_worker_id = ""
    for k, v in all_nodes.active_queues().items():
        if v[0].get('name', '') == 'analyze':
            cache_worker_id = k
    return cache_worker_id


