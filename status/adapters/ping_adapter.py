# Ping Status Adapter
import shlex
from subprocess import run
from django.conf import settings
from django.utils.encoding import smart_str
from common.response import json_response
import logging
logger = logging.getLogger("newt." + __name__)


def ping(machine_name, hostname):
    # Do a single ping with timeout 10 seconds
    args = shlex.split(smart_str('ping -c1 -t10 %s' % hostname))
    p = run(args)
    retcode = p.returncode 
    if retcode == 0:
        return {'system': machine_name, 'status': 'up'}
    else:
        return {'system': machine_name, 'status': 'down'}


def get_status(machine_name=None):
    """ Returns the status of a given machine (if machine_name is set),
        otherwise the statuses of all the machines

    Keyword arguments
    machine_name -- (optional) name of the machine
    """
    conf = settings.NEWT_CONFIG

    if machine_name is None:
        return [ping(s['NAME'], s['HOSTNAME']) for s in conf['SYSTEMS']]
    else:
        hostname = None
        for s in conf['SYSTEMS']:
            if machine_name == s['NAME']:
                hostname = s['HOSTNAME']
                break

        if hostname is None:
            return json_response(status="ERROR",
                                 status_code=404,
                                 error="Unrecognized system: %s" % machine_name)
        return ping(machine_name, hostname)

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
