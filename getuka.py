import requests
import json
import re
import os.path
import urllib
import logging
import hashlib
import sys

sessionId = ''
config = {}

OK_STATUS = 200
ERROR_STATUS = 452
USER_NOT_LOGGED_IN_STATUS = 453


def load_data_from_gerrit(relation):
    try:
        r = '&'.join(['q=status:open%20'+relation+':'+user+'&o=DETAILED_LABELS&o=MESSAGES' for user in config['gerrit']['users']])
        query = config['gerrit']['url'] + '/changes/?' + r
        resp = requests.get(query)
        return json.loads(resp.content[5:])
    except:
        logging.error("error while calling gerrit")
        logging.error("request: " + str(query))
        logging.error("response: " + str(resp))
        return None


def execute_kanbanik_command(json_data):
    if json_data is None:
        # nothing to do
        return

    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}

    resp = requests.post(config['kanbanik']['url'], data='command='+json.dumps(json_data), headers=headers)
    if resp.status_code == OK_STATUS:
        return resp.json()

    if resp.status_code == ERROR_STATUS or resp.status_code == USER_NOT_LOGGED_IN_STATUS:
        logging.error("error while calling kanbanik")
        logging.error("response: " + str(resp.status_code))
        logging.error("request: " + str(json_data))
        return None


def load_data_from_kanbanik():
    return execute_kanbanik_command({'commandName':'getTasks','includeDescription':True,'sessionId': sessionId})['values']


def parse_metadata_from_kanbanik(text):
    match_obj = re.match( r'.*\$GERRIT-ID;(.*);TIMESTAMP;(.*)\$.*', text, re.S|re.I)
    if match_obj:
        return match_obj.group(1), match_obj.group(2)
    else:
        return '', ''


def initialize(config_file):
    global sessionId
    global config

    with open(config_file) as data_file:
        config = json.load(data_file)

    sessionId = execute_kanbanik_command({'commandName':'login','userName': config['kanbanik']['user'] ,'password': config['kanbanik']['password']})['sessionId']


def gerrit_task_to_add_command(gerrit):
    res = as_kanbanik_task(gerrit)
    res['commandName'] = 'createTask'
    return res


def find_mapping_with_default(mapping, value):
    res = mapping['default']
    if value in mapping:
        res = mapping[value]

    return res

def add_assignee(kanbanik, gerrit):
    name = find_mapping_with_default(config['gerrit2kanbanikMappings']['user2kanbanikUser'], gerrit['owner']['name'])
    kanbanik['assignee'] = {'userName': name, 'realName': 'fake', 'pictureUrl': 'fake', 'sessionId': 'fake', 'version': 1}


def add_topic_as_tag(kanbanik, gerrit):
    if 'topic' not in gerrit:
        return

    topic = gerrit['topic']
    color = '#' + str(hashlib.sha224(topic).hexdigest()[:6])
    kanbanik['taskTags'].append([{'name': topic, 'description': topic, 'colour': color}])


def add_tags(kanbanik, gerrit):
    url = config['gerrit']['url'] + '/' + str(gerrit['_number'])
    kanbanik['taskTags'] = [{'name': 'G', 'description': 'Gerrit Link', 'onClickUrl': url, 'onClickTarget': 1, 'colour': 'green'}]
    add_labels_as_tags(kanbanik, gerrit, 'Verified', 'V:')
    add_labels_as_tags(kanbanik, gerrit, 'Code-Review', 'CR:')
    add_labels_as_tags(kanbanik, gerrit, 'Continuous-Integration', 'CI:')
    add_topic_as_tag(kanbanik, gerrit)

def add_labels_as_tags(kanbanik, gerrit, label_in_json, label):
    values = find_labels_values(gerrit, label_in_json)
    if values is None:
        return

    for name, value in values:
        if name is None or value is None:
            continue

        if value != 0:
            color = 'green'
            if value < 0:
                color = 'red'
            kanbanik['taskTags'].append([{'name': label_in_json + str(value), 'description': label + " " + name + ': ' + str(value), 'colour': color}])


def find_labels_values(gerrit, label_in_json):
    if label_in_json not in gerrit['labels']:
        return None

    labels = gerrit['labels'][label_in_json]['all']

    return [extract_tuple_from_label(label) for label in labels]

def extract_tuple_from_label(label):
    if 'name' in label and 'value' in label:
        return (label['name'], label['value'])
    else:
        # ignore - unsupported
        return (None, None)

def to_class_of_service(gerrit):
    id = find_mapping_with_default(config['gerrit2kanbanikMappings']['status2classOfServiceMapping'], gerrit['status'])
    return {'id': id, 'name': 'fake', 'description': 'fake', 'colour': 'fake', 'version': 1},


def to_workflowitem_id(gerrit):
    mapping = 'branch2workflowitemMapping'
    if can_be_merged(gerrit):
        mapping = 'workflowitem2mergeReadyMapping'

    return find_mapping_with_default(config['gerrit2kanbanikMappings']['owner'][mapping], gerrit['branch'])


def can_be_merged(gerrit):
    code_reviewed = False
    verifyed = False
    continues_integration_passed = False

    for name, value in find_labels_values(gerrit, 'Code-Review'):
        if value == 2:
            code_reviewed = True
            break

    if not code_reviewed:
        return False

    for name, value in find_labels_values(gerrit, 'Verified'):
        if value == 1:
            verifyed = True
            break

    if not verifyed:
        return False

    for name, value in find_labels_values(gerrit, 'Continuous-Integration'):
        if value == 1:
            continues_integration_passed = True
            break

    return continues_integration_passed

def gerrit_task_to_edit_command(gerrit, managed_kanbanik_tasks, force_update):
    corrsponding_task = find_changed_task(gerrit, managed_kanbanik_tasks, force_update)
    edit_task = as_kanbanik_task(gerrit)
    edit_task['commandName'] = 'editTask'
    edit_task['id'] = corrsponding_task['id']
    edit_task['ticketId'] = corrsponding_task['ticketId']
    # move explicitly
    edit_task['workflowitemId'] = corrsponding_task['workflowitemId']

    new_workflowitem = to_workflowitem_id(gerrit)
    res = [edit_task]
    if new_workflowitem != corrsponding_task['workflowitemId']:
        to_move = corrsponding_task.copy()
        to_move['workflowitemId'] = new_workflowitem
        to_move['version'] = to_move['version'] + 1
        res.append({
            'commandName': 'moveTask',
            'task': to_move,
            'sessionId': sessionId
        })

    return res


def as_kanbanik_task(gerrit):
    res = {
       'name': sanitize_string(gerrit['subject']),
       'description': '$GERRIT-ID;'+ gerrit['id']  +';TIMESTAMP;'+ gerrit['updated'] +'$',
       'workflowitemId': to_workflowitem_id(gerrit),
       'version':1,
       'projectId': config['kanbanik']['projectId'],
       'boardId': config['kanbanik']['boardId'],
       'classOfService': to_class_of_service(gerrit),
       'sessionId': sessionId,
       'order': 0
    }

    add_assignee(res, gerrit)
    add_tags(res, gerrit)

    return res


def move_kanbanik_to_unknown(kanbanik):
    current_workflowitem = kanbanik[1]['workflowitemId']
    already_in_changed = current_workflowitem  in [v for k, v in config["gerrit2kanbanikMappings"]['owner']["workflowitem2doneMapping"].items()]

    if already_in_changed:
        return None

    next_workflowitem = find_mapping_with_default(config["gerrit2kanbanikMappings"]['owner']["workflowitem2doneMapping"], current_workflowitem)

    kanbanik[1]['workflowitemId'] = next_workflowitem
    return {
        'commandName': 'moveTask',
        'task': kanbanik[1],
        'sessionId': sessionId
    }


def find_changed_task(gerrit_task, managed_kanbanik_tasks, force_update):
    for kanbanik_task in managed_kanbanik_tasks:
        if kanbanik_task[0][0] == gerrit_task['id'] and (kanbanik_task[0][1] != gerrit_task['updated'] or force_update):
            return kanbanik_task[1]
        elif kanbanik_task[0][0] == gerrit_task['id']:
            return None
    return None


def do_synchronize(relation, force_update = False):
    loaded = load_data_from_kanbanik()
    kanbanik_tasks = [(parse_metadata_from_kanbanik(task.get('description', '')), task) for task in loaded]

    managed_kanbanik_tasks = filter(lambda x: x[0] != ('', ''), kanbanik_tasks)
    managed_task_ids = [kanbanik_task[0][0] for kanbanik_task in managed_kanbanik_tasks]

    linearized_gerrit_tasks = [item for sublist in load_data_from_gerrit(relation) for item in sublist]

    # add new tasks
    to_add = [gerrit_task_to_add_command(gerrit_task) for gerrit_task in linearized_gerrit_tasks if gerrit_task['id'] not in managed_task_ids]
    for task_to_add in to_add:
        execute_kanbanik_command(task_to_add)

    # update existing
    to_edit = [gerrit_task_to_edit_command(gerrit_task, managed_kanbanik_tasks, force_update) for gerrit_task in linearized_gerrit_tasks if find_changed_task(gerrit_task, managed_kanbanik_tasks, force_update) is not None]
    for task_to_edit in to_edit:
        for one_command in task_to_edit:
            execute_kanbanik_command(one_command)

    # move out disappeared
    gerrit_task_ids = [gerrit_task['id'] for gerrit_task in linearized_gerrit_tasks]
    [execute_kanbanik_command(move_kanbanik_to_unknown(kanbanik_task)) for kanbanik_task in managed_kanbanik_tasks if kanbanik_task[0][0] not in gerrit_task_ids]


def sanitize_string(s):
    without_non_ascii = "".join(i for i in s if ord(i)<128)
    with_correct_enters = "<br>".join(without_non_ascii.split("\n"))
    without_json_special_chars = re.sub(r'"', '\'', with_correct_enters)
    return urllib.quote_plus(without_json_special_chars)


def read_opts(argv):
    if len(argv) == 1:
        return argv[0]
    else:
        return '/etc/getuka/getuka.json'

if __name__ == "__main__":
    config_file = read_opts(sys.argv[1:])

    lock_file_path = '/tmp/getuka.lock'
    logging.basicConfig(filename='/var/log/getuka.log',level=logging.DEBUG)
    logging.info("getuka started")

    if not os.path.isfile(lock_file_path):
        open(lock_file_path, 'w+')
    else:
        msg = "The lock file already exists at " + lock_file_path + ' - if you are sure no other instance of getuka is running, please delete it and run getuka again.'
        logging.error(msg)
        raise Exception(msg)

    initialize(config_file)

    try:
        logging.info("going to process")
        do_synchronize('owner', False)
        logging.info("process ended successfully")
        # not yet implemented
        # do_synchronize('reviewer')
    finally:
        try:
            execute_kanbanik_command({'commandName': 'logout', 'sessionId': sessionId})
        finally:
            os.remove(lock_file_path)

