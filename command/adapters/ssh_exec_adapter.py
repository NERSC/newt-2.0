from django.conf import settings
from common.shell import run_ssh_command
from common.response import json_response
import logging
logger = logging.getLogger("newt." + __name__)

def execute(request, machine_name, command):
    conf = settings.NEWT_CONFIG
    for s in conf['SYSTEMS']:
        if machine_name == s['NAME']:
            hostname = s['HOSTNAME']
            break
    try:
        (output, error, retcode) = run_ssh_command(request,command,hostname)
        response = {
            'output': output.decode("utf-8"),
            'error': error.decode("utf-8"),
            'retcode': retcode
        }
        return response
    except Exception as e:
        logger.error("Could not run command: %s" % str(e))
        return json_response(error="Could not run command: %s" % str(e), status="ERROR", status_code=500)


def get_systems(request):
    return ['localhost']

patterns = (
)

def extras_router(request, query):
    """Maps a query to a function if the pattern matches and returns result

    Keyword arguments:
    request -- Django HttpRequest
    query -- the query to be matched against
    """
    for pattern, func, req in patterns:
        match = pattern.match(query)
        if match and req:
            return func(request, **match.groupdict())
        elif match:
            return func(**match.groupdict())

    # Returns an Unimplemented response if no pattern matches
    return json_response(status="Unimplemented", 
                             status_code=501, 
                             error="", 
                             content="query: %s" % query)