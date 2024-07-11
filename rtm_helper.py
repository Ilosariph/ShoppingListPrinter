import os
from datetime import datetime

import requests
import hashlib
import xmltodict
import logging


try:
    loglevel = int(os.environ['LOG_LEVEL'])
except KeyError:
    loglevel = logging.INFO
logger = logging.getLogger(__name__)
logger.setLevel(loglevel)


api_key = os.getenv('API_KEY', '')
sharedSecret = os.getenv('SHARED_SECRET', '')
if api_key == '' or sharedSecret == '':
    logger.error('API key and shared secret must be set')
    exit(1)

auth_token = os.getenv('AUTH_TOKEN', '')
frob = os.getenv('FROB', '')
timeline = None

active_list_name = os.getenv('ACTIVE_LIST', '')

try:
    log_sensitive = int(os.environ['LOG_SENSITIVE']) == 1
except KeyError:
    log_sensitive = False


def build_url(base_url='https://www.rememberthemilk.com/services/rest/', append_default=True, **api_params):
    """
    Builds a rtm api url, appending all the params and generating and appending the required signature
    :param base_url: the base url to use. Afaik it doesn't need to be changed except for authentication.
    :param append_default: whether to append the default parameters. If true the api key, auth token and frob will be appended to the url.
    Afaik these are required for any functions except authentication.
    :param api_params: the params to append to the url
    :return: a finished url for the rtm api with all the required params and the signature
    """
    if base_url[-1] != '?':
        base_url = base_url + '?'
    url = base_url

    if append_default:
        logger.debug('appending default params')
        api_params.update({'api_key': api_key, 'auth_token': auth_token, 'from': frob})

    for k, v in api_params.items():
        url = url + f'{k}={v}&'

    if log_sensitive:
        logger.debug(f'URL after appending all params except the signature: {url}')

    sorted_args = sorted(api_params.items())
    secret_string = sharedSecret + ''.join(i + j for i, j in sorted_args)
    api_sig = hashlib.md5(secret_string.encode())

    url = url + f'api_sig={api_sig.hexdigest()}'

    if log_sensitive:
        logger.debug(f'URL after appending all the params with the signature: {url}')

    return url


def get_token():
    """
    Gets the auth token with the frob and api key
    :return: the response text of the request
    """
    get_token_url = build_url(append_default=False, method='rtm.auth.getToken', api_key=api_key, frob=frob)
    return requests.get(get_token_url).text


def has_error(response_text):
    error = True
    try:
        return xmltodict.parse(response_text)['rsp']['err'] is not None
    except KeyError:
        error = False
        return False
    finally:
        if error:
            logger.warning(f'An error occurred: {response_text}')


def get_timeline():
    """
    :return: A timeline. if no timeline exists a new timeline is created. For each restart a new timeline is created.
    """
    global timeline
    if timeline is None:
        get_timeline_url = build_url(method='rtm.timelines.create')
        timeline = xmltodict.parse(requests.get(get_timeline_url).text)['rsp']['timeline']
    return timeline


def set_list_name(list_id, name):
    """
    :param list_id: the id of the list for which to change the name
    :param name: the new name
    :return: whether the change was successful
    """
    set_name_url = build_url(method='rtm.lists.setName', timeline=get_timeline(), list_id=list_id, name=name)
    return not has_error(requests.get(set_name_url).text)


def get_lists(include_archived=False):
    """
    :param include_archived: whether to include archived lists
    :return: a list of all lists available. Each list is a dict with entries like @id and @name
    """
    get_lists_url = build_url(method='rtm.lists.getList')
    list_dict = xmltodict.parse(requests.get(get_lists_url).text)
    if include_archived:
        return list_dict['rsp']['lists']['list']
    return [list for list in list_dict['rsp']['lists']['list'] if list['@archived'] == '0']


def archive_list(list_id):
    """
    :param list_id: the id of the list to be archived
    :return: whether the list was successfully archived
    """
    archive_list_url = build_url(method='rtm.lists.archive', timeline=get_timeline(), list_id=list_id)
    return not has_error(requests.get(archive_list_url).text)


def add_list(name):
    """
    :param name: the name of the list to be added
    :return: the id of the added list
    :throws KeyError if something went wrong
    """
    add_list_url = build_url(method='rtm.lists.add', timeline=get_timeline(), name=name)
    response = requests.get(add_list_url).text
    try:
        return not xmltodict.parse(response)['rsp']['list']['@id']
    except KeyError:
        raise KeyError(f'The id of the created list could not be found. Response: {response}')


def get_tasks(list_id):
    """
    Gets all tasks from a list
    :param list_id: the id of the list
    :return: a list of all tasks as a dict. Each task is a dict with keys a few keys. The only one I use is @name
    """
    get_tasks_url = build_url(method='rtm.tasks.getList', list_id=list_id)
    return xmltodict.parse(requests.get(get_tasks_url).text)['rsp']['tasks']['list']['taskseries']


def get_task_names(list_id):
    """
    Gets all the tasks from a list in an easily readable format
    :param list_id: the id of the list
    """
    tasks = get_tasks(list_id)
    return [task['@name'] for task in tasks]


def get_list_id_by_name(name):
    """
    Gets the id of a list from the list name. Doesn't include archived lists.
    :param name: the name of the list
    """
    lists = get_lists()
    for list in lists:
        if list['@name'] == name:
            return list['@id']


def auth():
    global frob, auth_token

    if frob != '' and auth_token != '':
        check_token_url = build_url(append_default=False, method='rtm.auth.checkToken', api_key=api_key, auth_token=auth_token)
        if not has_error(requests.get(check_token_url).text):
            logger.info('Valid token and frob')
            return
        logger.warning('Token and / or frob not valid')

    if frob == '':
        frob_url = build_url(append_default=False, method='rtm.auth.getFrob', api_key=api_key)
        response = requests.get(frob_url)
        frob = xmltodict.parse(response.text)['rsp']['frob']

    token_response = get_token()
    # I don't know any case where this would work without authenticating, so this should always be true
    if has_error(token_response):
        auth_url = build_url('https://www.rememberthemilk.com/services/auth/', append_default=False, api_key=api_key, perms='delete', frob=frob)
        logger.info(f'Please authenticate at {auth_url}, and set the frob to "{frob}". Then restart the application.')
    if auth_token == '':
        auth_token = xmltodict.parse(token_response)['rsp']['auth']['token']
        logger.info(f'Please set the auth token to "{auth_token}". Then restart the application.')


def get_items_to_buy():
    id = get_list_id_by_name(active_list_name)
    logger.debug(f'Getting items to buy for list {active_list_name} with id {id}')
    items = get_task_names(id)
    logger.debug(f'Found {items} in list {active_list_name}')
    old_list_name = active_list_name + ' ' + datetime.now().strftime('%d.%m.%Y %H:%M')
    logger.debug(f'Setting the name of {active_list_name} to {old_list_name}')
    set_list_name(id, old_list_name)
    logger.debug(f'Archiving {old_list_name}')
    archive_list(id)
    logger.debug(f'Creating new list with the name {active_list_name}')
    new_list_id = add_list(active_list_name)
    logger.debug(f'Created a new list with the name {active_list_name} and id {new_list_id}')
    logger.info(f'Successfully retrieved the items ({items}) from the old list, archived it and created a new list.')
    return '\n'.join(items)


auth()
