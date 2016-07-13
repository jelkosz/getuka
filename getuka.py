import requests
import json
import re
import os.path
import urllib
import logging
import hashlib
import sys
import getopt

sessionId = ''
config = {}

OK_STATUS = 200
ERROR_STATUS = 452
USER_NOT_LOGGED_IN_STATUS = 453

# needed since gerrit has a limit for query to 10 so this part has to be sliced
GERRIT_NUM_OF_USERS_SLICE = 3

def load_data_from_gerrit():
    res = []
    _load_recursive(config['gerrit']['users'], res)
    return res


def _load_recursive(slice, res):
    if len(slice) > GERRIT_NUM_OF_USERS_SLICE:
        for sliceres in _load_data_from_gerrit(slice[0: GERRIT_NUM_OF_USERS_SLICE]):
            res.append(sliceres)
        _load_recursive(slice[GERRIT_NUM_OF_USERS_SLICE:], res)
    else:
        for sliceres in _load_data_from_gerrit(slice):
            res.append(sliceres)


def _load_data_from_gerrit(users):
    try:
        r = '&'.join(['q=owner:'+user+'&o=DETAILED_LABELS&o=COMMIT_FOOTERS&o=CURRENT_COMMIT&o=CURRENT_REVISION' for user in users]) + '&n=100'
        query = config['gerrit']['url'] + '/changes/?' + r
        resp = requests.get(query)
        return [item for sublist in json.loads(resp.content[5:]) for item in sublist]
    except:
        logging.error("error while calling gerrit")
        logging.error("request: " + str(query))
        logging.error("response: " + str(resp))
        raise Exception('Error while communicating with gerrit, please see logs for more details')


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
        raise Exception('Error communicating with kanbanik - please see logs for more details')


def load_data_from_kanbanik():
    return execute_kanbanik_command({'commandName':'getTasks','includeDescription':True,'sessionId': sessionId})['values']


def parse_metadata_from_kanbanik(text):
    match_obj = re.match( r'.*\$GERRIT-ID;(.*);TIMESTAMP;(.*)\$.*', text, re.S|re.I)
    if match_obj:
        return match_obj.group(1), match_obj.group(2)
    else:
        return '', ''


def initialize(config_file, kanbanik_pass):
    global sessionId
    global config

    with open(config_file) as data_file:
        config = json.load(data_file)

    if kanbanik_pass is not None:
        config['kanbanik']['password'] = kanbanik_pass
    
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

# todo during some cleanup this will anyway be removed
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


def get_gerrit_score(gerrit, label_in_json):
    values = find_labels_values(gerrit, label_in_json)
    if values is None:
        return []

    return [value for value in values if value is not None]

def find_labels_values(gerrit, label_in_json):
    if label_in_json not in gerrit['labels']:
        return None

    labels = gerrit['labels'][label_in_json]['all']

    return [extract_tuple_from_label(label) for label in labels]

def extract_tuple_from_label(label):
    if 'value' in label:
        return label['value']
    else:
        # ignore - unsupported
        return None

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
       'version': 1,
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


def parse_bz_ids_from_gerrit_commit(msg):
    match_obj = re.findall('.*Bug-Url.*[=//]([0-9]+).*\n', msg, re.I|re.MULTILINE)
    return [res for res in match_obj]


def parse_change_id_from_gerrit_commit(msg):
    match_obj = re.findall('.*Change-Id: (.*)\n', msg, re.I|re.MULTILINE)
    return [res for res in match_obj]


def parse_provided_ids_from_gerrit_task(gerrit_task, id_parser):
    try:
        msg = gerrit_task['revisions'].values()[0]['commit']['message']
        return id_parser(msg)
    except:
        return []

    return []


#returns {provided_id -> [gerrit tasks]}
def parse_provided_id_from_gerrit_tasks(gerrit_tasks, id_provider, parser):
    res = {}
    for task in gerrit_tasks:
        for bz_id in id_provider(task, parser):
            if bz_id not in res:
                res[bz_id] = []

            res[bz_id].append(task)
    return res


def as_bzid_to_kanbanik_task(kanbanik_tasks):
    res = {}
    for kanbanik_task in kanbanik_tasks:
        for tag in kanbanik_task['taskTags']:
            if tag['name'].startswith('xbz:'):
                res[tag['name'][4:]] = kanbanik_task
                break

    return res

# ([scores as string], most important score)
def gerrit_score_as_string(gerrit, label):
    scores = [score for score in get_gerrit_score(gerrit, label)]
    cleared_scores = [str(score) for score in scores if score != 0]
    if len(cleared_scores) == 0:
        return '0', 0
    else:
        min_score = min(scores)
        if min_score < 0:
            return ', '.join(cleared_scores), min_score
        else:
            return ', '.join(cleared_scores), max(scores)


# returns true if something has changed, otherwise false
def get_tag_color(ciscore, color, cscore, gerrit, vscore):
    if gerrit['status'] == u'MERGED' or gerrit['status'] == u'ABANDONED':
        color = 'teal'
    else:
        if vscore == 0:
            color = 'orange'
        elif vscore == -1:
            color = 'red'

        if color == 'green':
            if cscore == 0 or cscore == 1:
                color = 'orange'
            elif cscore < 0:
                color = 'red'
        elif color == 'orange':
            if cscore < 0:
                color = 'red'

        if color == 'green':
            if ciscore == 0:
                color = 'orange'
            elif ciscore == -1:
                color = 'red'
        elif color == 'orange':
            if ciscore == -1:
                color = 'red'
    return color


def edit_tags(kanbanik_task, change_id, gerrits):
    names = ['xg: %i' % len(gerrits)]
    description = [change_id + ': ']

    color = 'green'
    for gerrit in gerrits:
        verified, vscore = gerrit_score_as_string(gerrit, 'Verified')
        cr, cscore = gerrit_score_as_string(gerrit, 'Code-Review')
        ci, ciscore = gerrit_score_as_string(gerrit, 'Continuous-Integration')

        color = get_tag_color(ciscore, color, cscore, gerrit, vscore)

        scores_string = '(v: %s, cr: %s, ci: %s)' % (verified, cr, ci)
        names.append(scores_string)
        description.append(str(gerrit['_number']) + '->' + scores_string + ', ')

    name = ' '.join(names)
    url = config['gerrit']['url'] + '/#/q/' + change_id

    new_tag = {'name': name, 'description': ''.join(description), 'onClickUrl': url, 'onClickTarget': 1, 'colour': color}

    new_tags = []
    add_needed = True
    update_kanbanik = False
    for tag in kanbanik_task['taskTags']:
        if tag['description'].startswith(change_id + ':'):
            add_needed = False

            if new_tag == tag:
                return False
            else:
                new_tags.append(new_tag)
                update_kanbanik = True

        else:
            new_tags.append(tag)

    if add_needed:
        update_kanbanik = True
        new_tags.append(new_tag)

    kanbanik_task['taskTags'] = new_tags

    return update_kanbanik

def do_synchronize_with_bz(force_update = False):
    kanbanik_tasks = load_data_from_kanbanik()
    gerri_data = load_data_from_gerrit()
    bz_to_gerrit_tasks = parse_provided_id_from_gerrit_tasks(gerri_data, parse_provided_ids_from_gerrit_task, parse_bz_ids_from_gerrit_commit)
    bzid_to_kanbanik_task = as_bzid_to_kanbanik_task(kanbanik_tasks)

    for bz_id, gerrit_tasks in bz_to_gerrit_tasks.items():
        if bz_id not in bzid_to_kanbanik_task:
            continue

        kanbanik_task = bzid_to_kanbanik_task[bz_id]
        gerrit_groupped_by_changeid = parse_provided_id_from_gerrit_tasks(gerrit_tasks, parse_provided_ids_from_gerrit_task, parse_change_id_from_gerrit_commit)
        to_update = False
        for change_id, gerrit_tasks in gerrit_groupped_by_changeid.items():
            if edit_tags(kanbanik_task, change_id, gerrit_tasks):
                to_update = True

        # if at least one change happened
        if to_update:
            kanbanik_task['description'] = sanitize_string(kanbanik_task['description'])
            kanbanik_task['commandName'] = 'editTask'
            kanbanik_task['sessionId'] = sessionId
            execute_kanbanik_command(kanbanik_task)


def do_synchronize(force_update = False):
    loaded = load_data_from_kanbanik()
    kanbanik_tasks = [(parse_metadata_from_kanbanik(task.get('description', '')), task) for task in loaded]

    managed_kanbanik_tasks = filter(lambda x: x[0] != ('', ''), kanbanik_tasks)
    managed_task_ids = [kanbanik_task[0][0] for kanbanik_task in managed_kanbanik_tasks]

    linearized_gerrit_tasks = load_data_from_gerrit()

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


def synchronize(kanbanik_pass, config_file):
    logging.basicConfig(filename='/var/log/getuka.log',level=logging.DEBUG)
    logging.info("getuka started")

    if not os.path.isfile(lock_file_path):
        open(lock_file_path, 'w+')
    else:
        msg = "The lock file already exists at " + lock_file_path + ' - if you are sure no other instance of getuka is running, please delete it and run getuka again.'
        logging.error(msg)
        raise Exception(msg)

    initialize(config_file, kanbanik_pass)

    try:
        logging.info("going to process")
        do_synchronize_with_bz(False)
        logging.info("process ended successfully")
    finally:
        try:
            execute_kanbanik_command({'commandName': 'logout', 'sessionId': sessionId})
        finally:
            os.remove(lock_file_path)


if __name__ == "__main__":
# ok, the handling of the cmd line is a pain, needs to be fixed soon
    config_file = None
    kanbanik_pass = None
    lock_file_path = '/tmp/getuka.lock'

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hk:c:", ["kanbanikpass=", "config="])
    except getopt.GetoptError:
        print 'getuka.py -k <kanbanik password> -c <config file path>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'getuka.py -k <kanbanik password> -c <config file path>'
            sys.exit()
        elif opt in ("-k", "--kanbanikpass"):
            kanbanik_pass = arg
        elif opt in ("-c", "--config"):
            config_file = arg

    synchronize(kanbanik_pass, config_file)