import requests
import json
import re
import os.path
import urllib
import logging
from datetime import datetime
import sys
import getopt

sessionId = ''
config = {}

OK_STATUS = 200
ERROR_STATUS = 452
USER_NOT_LOGGED_IN_STATUS = 453

# needed since gerrit has a limit for query to 10 so this part has to be sliced
GERRIT_NUM_OF_USERS_SLICE = 3

def load_data_from_gerrit(relation, slice_size, only_opened):
    res = []
    _load_recursive(config['gerrit']['users'], res, relation, slice_size, only_opened)
    return res


def _load_recursive(slice, res, relation, slice_size, only_opened):
    res.append(_load_data_from_gerrit(slice[0: slice_size], relation, only_opened))
    if len(slice) > slice_size:
        _load_recursive(slice[slice_size:], res, relation, slice_size, only_opened)

# the relation is either owner or reviewer
def _load_data_from_gerrit(users, relation, only_opened):
    additional_params = 'is:open+' if only_opened else ''
    try:
        r = '&'.join(['q=' + additional_params + relation + ':'+user+'&o=DETAILED_LABELS&o=COMMIT_FOOTERS&o=CURRENT_COMMIT&o=CURRENT_REVISION' for user in users]) + '&n=100'
        query = config['gerrit']['url'] + '/changes/?' + r
        resp = requests.get(query)
        # because gerrit api returns one list if asked for one user or a list of lists if asked for list of users
        if len(users) == 1:
            return (users, json.loads(resp.content[5:]))
        else:
            return (users, [item for sublist in json.loads(resp.content[5:]) for item in sublist])
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


def initialize(config_file, kanbanik_pass):
    global sessionId
    global config

    with open(config_file) as data_file:
        config = json.load(data_file)

    if kanbanik_pass is not None:
        config['kanbanik']['password'] = kanbanik_pass
    
    sessionId = execute_kanbanik_command({'commandName':'login','userName': config['kanbanik']['user'] ,'password': config['kanbanik']['password']})['sessionId']

def find_mapping_with_default(mapping, value):
    res = mapping['default']
    if value in mapping:
        res = mapping[value]

    return res


def as_kanbanik_user_name(gerrit):
    return find_mapping_with_default(config['gerrit2kanbanikMappings']['userSpecificMappings'], str(gerrit['owner']['_account_id']))['kanbanikName']


def add_assignee(kanbanik, gerrit):
    name = as_kanbanik_user_name(gerrit)
    kanbanik['assignee'] = {'userName': name, 'realName': 'fake', 'pictureUrl': 'fake', 'sessionId': 'fake', 'version': 1}


def add_topic_as_tag(kanbanik, gerrit):
    topic = parse_topic_from_gerrit(gerrit)[0]
    url = config['gerrit']['url'] + '/#/q/topic:' + str(topic)
    if 'taskTags' not in kanbanik:
        kanbanik['taskTags'] = []

    kanbanik['taskTags'].append({'name': 'xt:' + str(topic), 'description': topic, 'colour': 'Transparent', 'onClickUrl': url})


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


def can_be_merged(gerrit):
    verified, vscore = gerrit_score_as_string(gerrit, 'Verified')
    cr, crcore = gerrit_score_as_string(gerrit, 'Code-Review')
    ci, ciscore = gerrit_score_as_string(gerrit, 'Continuous-Integration')
    return crcore == 2 and vscore == 1 and ciscore == 1


def as_simple_kanbanik_task(topic, gerrit, provide_project, provide_workflowitem_id):
    res = {
       'name': sanitize_string(topic),
       'description': 'Task for topic: ' + str(topic),
       'workflowitemId': provide_workflowitem_id(None),
       'version': 1,
       'projectId': provide_project(gerrit),
       'boardId': config['kanbanik']['boardId'],
       'classOfService': to_class_of_service(gerrit),
       'sessionId': sessionId,
       'order': 0
    }

    add_topic_as_tag(res, gerrit)
    add_assignee(res, gerrit)
    return res

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


#returns (<not bound to ID, <bound to ID in format: {provided_id -> [gerrit tasks]}>)
def parse_provided_id_from_gerrit_tasks(gerrit_tasks, id_provider, parser):
    id_binding = {}
    not_bound = []
    for task in gerrit_tasks:
        bound_ids = id_provider(task, parser)
        if len(bound_ids) == 0:
            not_bound.append(task)
        else:
            for bound_id in bound_ids:
                if bound_id not in id_binding:
                    id_binding[bound_id] = []

                id_binding[bound_id].append(task)
    return (not_bound, id_binding)


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


def edit_tags(kanbanik_task, change_id, gerrits, tag_unique_part):
    names = [tag_unique_part + ' ' + str(len(gerrits))]
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
        updated = gerrit['updated'].split('.', 1)[0]
        updated_date = datetime.strptime(updated, '%Y-%m-%d %H:%M:%S')

    name = ' '.join(names)
    url = config['gerrit']['url'] + '/#/q/' + change_id

    new_tag = {'name': name, 'description': ''.join(description), 'onClickUrl': url, 'onClickTarget': 1, 'colour': color}

    new_tags = []
    add_needed = True
    update_kanbanik = False
    if 'taskTags' not in kanbanik_task:
        kanbanik_task['taskTags'] = []

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

def do_synchronize_with_bz(all_gerrit_data, kanbanik_tasks, force_update = False):
    bz_to_gerrit_tasks = parse_provided_id_from_gerrit_tasks(all_gerrit_data, parse_provided_ids_from_gerrit_task, parse_bz_ids_from_gerrit_commit)[1]
    bzid_to_kanbanik_task = as_bzid_to_kanbanik_task(kanbanik_tasks)

    for bz_id, gerrit_tasks in bz_to_gerrit_tasks.items():
        if bz_id not in bzid_to_kanbanik_task:
            continue

        kanbanik_task = bzid_to_kanbanik_task[bz_id]
        gerrit_groupped_by_changeid = parse_provided_id_from_gerrit_tasks(gerrit_tasks, parse_provided_ids_from_gerrit_task, parse_change_id_from_gerrit_commit)[1]
        to_update = False
        for change_id, gerrit_tasks in gerrit_groupped_by_changeid.items():
            if edit_tags(kanbanik_task, change_id, gerrit_tasks, 'xg:'):
                to_update = True

        # if at least one change happened
        if to_update:
            kanbanik_task['description'] = sanitize_string(kanbanik_task['description'])
            kanbanik_task['commandName'] = 'editTask'
            kanbanik_task['sessionId'] = sessionId
            execute_kanbanik_command(kanbanik_task)


def parse_topic_from_gerrit(gerrit):
    if 'topic' not in gerrit:
        return [gerrit['subject']]

    return [gerrit['topic']]


def parse_topic_from_kanbanik(kanbanik_task, tag_unique_part):
    for tag in kanbanik_task['taskTags']:
        if tag['name'].startswith(tag_unique_part):
            return tag['name'][3:]
    return None


def group_by_user(tasks, extract_user):
    res = {}
    for task in tasks:
        user_id = extract_user(task)
        if user_id not in res:
            res[user_id] = []
        res[user_id].append(task)

    return res

def do_synchronize_standalone_one(user_id, gerrits_of_user, kanbanik_tasks_by_user, tag_unique_part, provide_project, provide_workflowitem_id):
        # [(topic -> [gerrit tasks])]
        gerrit_data = parse_provided_id_from_gerrit_tasks(gerrits_of_user, lambda task, parser: parser(task), parse_topic_from_gerrit)[1]

        # {topic -> kanbanik task}
        managed_kanbanik_tasks = {}
        if user_id in kanbanik_tasks_by_user:
            managed_kanbanik_tasks = dict([(parse_topic_from_kanbanik(task, tag_unique_part), task) for task in kanbanik_tasks_by_user[user_id] if parse_topic_from_kanbanik(task, tag_unique_part) is not None])

        for topic, gerrit_tasks in gerrit_data.iteritems():
            if topic not in managed_kanbanik_tasks:
                # create new taks
                active_gerrit_tasks = [task for task in gerrit_tasks if task['status'] != 'MERGED' and task['status'] != 'ABANDONED']
                if len(active_gerrit_tasks) == 0:
                    # stop managing old merged tasks
                    continue
                kanbanik_task = as_simple_kanbanik_task(topic, gerrit_tasks[0], provide_project, provide_workflowitem_id)
            else:
                kanbanik_task = managed_kanbanik_tasks[topic]
                kanbanik_task['workflowitemId'] = provide_workflowitem_id(kanbanik_task)


            gerrit_groupped_by_changeid = parse_provided_id_from_gerrit_tasks(gerrit_tasks, parse_provided_ids_from_gerrit_task, parse_change_id_from_gerrit_commit)[1]
            to_update = False
            for change_id, gerrit_tasks in gerrit_groupped_by_changeid.items():
                if edit_tags(kanbanik_task, change_id, gerrit_tasks, tag_unique_part):
                    to_update = True

            # if at least one change happened or something has been added
            if to_update:
                if 'description' in kanbanik_task:
                    kanbanik_task['description'] = sanitize_string(kanbanik_task['description'])
                kanbanik_task['commandName'] = 'editTask'
                kanbanik_task['sessionId'] = sessionId
                execute_kanbanik_command(kanbanik_task)

def do_synchronize_standalone(all_gerrit_data, kanbanik_tasks_by_user, force_update = False):
    # {kanbanik user id -> [gerrit task]}
    for user_id, gerrits_of_user in group_by_user(all_gerrit_data, lambda task: as_kanbanik_user_name(task)).iteritems():
        active_gerrits = [gerrit for gerrit in gerrits_of_user if gerrit['status'] != 'MERGED' and gerrit['status'] != 'ABANDONED']
        do_synchronize_standalone_one(user_id, active_gerrits, kanbanik_tasks_by_user, 'xg',
                                      lambda gerrit: find_mapping_with_default(config['gerrit2kanbanikMappings']['userSpecificMappings'], str(gerrit['owner']['_account_id']))['projectId'],
                                      lambda kanbanik: config['gerrit2kanbanikMappings']['owner']['workflowitemId']
                                      )


def sanitize_string(s):
    without_non_ascii = "".join(i for i in s if ord(i)<128)
    with_correct_enters = "<br>".join(without_non_ascii.split("\n"))
    without_json_special_chars = re.sub(r'"', '\'', with_correct_enters)
    return urllib.quote_plus(without_json_special_chars)


def do_synchronize_reviewer(kanbanik_tasks_by_user, reviewer_gerrit_data):
    # {kanbanikUserName -> gerrit_user_id}
    reverse_user_mapping = {}
    for key, value in config['gerrit2kanbanikMappings']['userSpecificMappings'].iteritems():
        reverse_user_mapping[value['kanbanikName']] = key

    def provide_project(kanbanik_name):
        return lambda gerrit: \
            config['gerrit2kanbanikMappings']['userSpecificMappings'][reverse_user_mapping[kanbanik_name]]['projectId'] \
                if kanbanik_name in reverse_user_mapping \
                else config['gerrit2kanbanikMappings']['userSpecificMappings']['default']['projectId']

    def provide_workflowitem_id(kanbanik):
        if kanbanik is None:
            return config['gerrit2kanbanikMappings']['reviewer']['backlogId']
        elif kanbanik['workflowitemId'] in config['gerrit2kanbanikMappings']['reviewer']['allowedTransitions']:
            return config['gerrit2kanbanikMappings']['reviewer']['allowedTransitions'][kanbanik['workflowitemId']]
        else:
            kanbanik['workflowitemId']

    for reviewer_data in reviewer_gerrit_data:
        kanbanik_name = find_mapping_with_default(config['gerrit2kanbanikMappings']['user2kanbanikUser'],
                                                  reviewer_data[0][0])
        do_synchronize_standalone_one(kanbanik_name, reviewer_data[1], kanbanik_tasks_by_user, 'xgr:',
                                      provide_project(kanbanik_name),
                                      provide_workflowitem_id)


def synchronize(kanbanik_pass, config_file):
    lock_file_path = '/tmp/getuka.lock'

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
        witout_user = [data[1] for data in load_data_from_gerrit('owner', GERRIT_NUM_OF_USERS_SLICE, False)]
        gerrit_data = [item for sublist in witout_user for item in sublist]

        loaded_kanbanik_tasks = load_data_from_kanbanik()

        # {kanbanik user id -> [kanbanik tasks]}
        kanbanik_tasks_by_user = group_by_user([task for task in loaded_kanbanik_tasks if 'assignee' in task], lambda task: task['assignee']['userName'])

        # do_synchronize_with_bz(gerrit_data, loaded_kanbanik_tasks, False)
        # do_synchronize_standalone(gerrit_data, kanbanik_tasks_by_user, False)

        # [([userid], [gerrit tasks])]
        reviewer_gerrit_data = load_data_from_gerrit('reviewer', 1, True)
        # with open('/tmp/data.txt', 'w') as outfile:
        #     json.dump(reviewer_gerrit_data, outfile)

        # with open('/tmp/data.txt') as data_file:
        #     gerrit_data = json.load(data_file)


        do_synchronize_reviewer(kanbanik_tasks_by_user, reviewer_gerrit_data)

        logging.info("process ended successfully")
    finally:
        try:
            execute_kanbanik_command({'commandName': 'logout', 'sessionId': sessionId})
        finally:
            os.remove(lock_file_path)


if __name__ == "__main__":
    config_file = None
    kanbanik_pass = None

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