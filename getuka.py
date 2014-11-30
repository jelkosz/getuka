import requests
import json
import re

sessionId = ''
config = {}

OK_STATUS = 200
ERROR_STATUS= 452
USER_NOT_LOGGED_IN_STATUS = 453


def load_data_from_gerrit(relation):
    r = '&'.join(['q=status:open%20'+relation+':'+user+'&o=DETAILED_LABELS&o=MESSAGES' for user in config['gerrit']['users']])
    query = config['gerrit']['url'] + '/changes/?' + r
    resp = requests.get(query)
    return json.loads(resp.content[5:])


def execute_kanbanik_command(json_data):
    if json_data is None:
        # nothing to do
        return

    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}

    resp = requests.post(config['kanbanik']['url'], data='command='+json.dumps(json_data), headers=headers)
    if resp.status_code == OK_STATUS:
        return resp.json()

    if resp.status_code == ERROR_STATUS or resp.status_code == USER_NOT_LOGGED_IN_STATUS:
        raise Exception('Error while calling server. Status code: '+ str(resp.status_code) + '. Resp: ' + resp.text)


def load_data_from_kanbanik():
    return execute_kanbanik_command({'commandName':'getTasks','includeDescription':True,'sessionId': sessionId})['values']


def parse_metadata_from_kanbanik(text):
    match_obj = re.match( r'.*\$GERRIT-ID;(.*);TIMESTAMP;(.*)\$.*', text, re.S|re.I)
    if match_obj:
        return match_obj.group(1), match_obj.group(2)
    else:
        return '', ''


def initialize():
    global sessionId
    global config

    with open('/etc/getuka/getuka.json') as data_file:
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


def to_class_of_service(gerrit):
    id = find_mapping_with_default(config['gerrit2kanbanikMappings']['status2classOfServiceMapping'], gerrit['status'])
    return {'id': id, 'name': 'fake', 'description': 'fake', 'colour': 'fake', 'version': 1},


def to_workflowitem_id(gerrit):
    return find_mapping_with_default(config['gerrit2kanbanikMappings']['owner']['branch2workflowitemMapping'], gerrit['branch'])


def gerrit_task_to_edit_command(gerrit, managed_kanbanik_tasks):
    corrsponding_task = find_changed_task(gerrit, managed_kanbanik_tasks)
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
       'name': gerrit['subject'],
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


def find_changed_task(gerrit_task, managed_kanbanik_tasks):
    for kanbanik_task in managed_kanbanik_tasks:
        if kanbanik_task[0][0] == gerrit_task['id'] and kanbanik_task[0][1] != gerrit_task['updated']:
            return kanbanik_task[1]
        elif kanbanik_task[0][0] == gerrit_task['id']:
            return None
    return None


def do_synchronize(relation):
    loaded = load_data_from_kanbanik()
    kanbanik_tasks = [(parse_metadata_from_kanbanik(task.get('description', '')), task) for task in loaded]

    managed_kanbanik_tasks = filter(lambda x: x[0] != ('', ''), kanbanik_tasks)
    managed_task_ids = [kanbanik_task[0][0] for kanbanik_task in managed_kanbanik_tasks]

    linearized_gerrit_tasks = [item for sublist in load_data_from_gerrit(relation) for item in sublist]
    # linearized_gerrit_tasks = [task for task in linearized_gerrit_tasks if task[]]

    # add new tasks
    to_add = [gerrit_task_to_add_command(gerrit_task) for gerrit_task in linearized_gerrit_tasks if gerrit_task['id'] not in managed_task_ids]
    for task_to_add in to_add:
        execute_kanbanik_command(task_to_add)

    # update existing
    to_edit = [gerrit_task_to_edit_command(gerrit_task, managed_kanbanik_tasks) for gerrit_task in linearized_gerrit_tasks if find_changed_task(gerrit_task, managed_kanbanik_tasks) is not None]
    for task_to_edit in to_edit:
        for one_command in task_to_edit:
            execute_kanbanik_command(one_command)

    # move out disappeared
    gerrit_task_ids = [gerrit_task['id'] for gerrit_task in linearized_gerrit_tasks]
    [execute_kanbanik_command(move_kanbanik_to_unknown(kanbanik_task)) for kanbanik_task in managed_kanbanik_tasks if kanbanik_task[0][0] not in gerrit_task_ids]

if __name__ == "__main__":
    initialize()

    try:
        do_synchronize('owner')
        # do_synchronize('reviewer')
    finally:
        execute_kanbanik_command({'commandName': 'logout', 'sessionId': sessionId})
