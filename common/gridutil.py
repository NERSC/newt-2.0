import shlex
import os
import urllib
import re
from authnz.models import Cred
import logging
logger = logging.getLogger("newt." + __name__)
from common.shell import run_command

GRID_RESOURCE_TABLE = dict(
     edison=dict(hostname='edisongrid.nersc.gov',
                 jobmanagers=dict(fork=dict(url="edisongrid.nersc.gov/jobmanager"),
                                  batch=dict()),
                 gridftp_servers=['edisongrid.nersc.gov'],
                 qstat=dict(bin='/project/projectdirs/osp/newt_tools/qs_slurm.sh', scheduler='sqs'),
                 qacct=dict(bin='/project/projectdirs/osp/newt_tools/sacct_wrapper.sh', scheduler='sacct'),
                 qsub=dict(bin='/usr/bin/sbatch', scheduler='slurm'),
                 qdel=dict(bin='/usr/bin/scancel', scheduler='slurm'),
                 ),
     cori=dict(hostname='corigrid.nersc.gov',
               jobmanagers=dict(fork=dict(url="corigrid.nersc.gov/jobmanager"),
                                batch=dict()),
               gridftp_servers=['corigrid.nersc.gov'],
               qstat=dict(bin='/project/projectdirs/osp/newt_tools/qs_slurm.sh', scheduler='sqs'),
               qacct=dict(bin='/project/projectdirs/osp/newt_tools/sacct_wrapper.sh', scheduler='sacct'),
               qsub=dict(bin='/usr/bin/sbatch', scheduler='slurm'),
               qdel=dict(bin='/usr/bin/scancel', scheduler='slurm'),
               ),
    datatran=dict(
        hostname='dtn01.nersc.gov', 
        jobmanagers=dict(),
        gridftp_servers=['dtn01.nersc.gov','dtn02.nersc.gov'],
        qstat=dict(),
    ),
    archive=dict(
        hostname='garchive.nersc.gov', 
        jobmanagers=dict(),
        gridftp_servers=['garchive.nersc.gov'],
        qstat=dict(),
    )
)

MYPROXY_CONFIG = dict(
    SERVER="nerscca2.nersc.gov",
    PATH="/global/scratch2/sd/tsun/",
    PREFIX="newt_x509up_u",
)

GLOBUS_CONF = {
    "LOCATION": "/global/common/datatran/dsg/globus-5.0.4/",
    "TCP_PORT_RANGE": "60000,65000",
    "HOSTNAME": "newt.nersc.gov",
    "LIB_PATH": "/global/common/datatran/dsg/globus-5.0.4/lib/"
}

SGE_EXECD_PORT = "537"
SGE_QMASTER_PORT = "536"
SGE_ROOT = "/common/nsg/sge/ge-8.1.2"

def is_sanitized(input):
    return not re.search(r'[^ a-zA-Z0-9!@#%^_+:./-]', input)

def get_cred_env(user):
    """Creates a cert file for the user and returns the environment

    Keyword arguments:
    user -- django.contrib.auth.model.user object
    """
    def create_cert(path, data):
        logger.debug("Creating x509 cert in directory: %s" % path)
        oldmask=os.umask(077)
        f = file(path,'w')
        f.write(data)
        f.close()
        os.umask(oldmask)

    try:
        cred = Cred.objects.filter(user=user)[0]
    except IndexError:
        logger.error("No credentials found for user: %s" % user.username)
        raise Exception("No credentials found for user: %s" % user.username)

    cred_path = os.path.join(MYPROXY_CONFIG['PATH'], 
                             MYPROXY_CONFIG['PREFIX'] + user.username)
    create_cert(cred_path, cred.cert + cred.key + cred.calist)

    env = os.environ.copy()
    env['X509_USER_PROXY'] = cred_path
    env['GLOBUS_LOCATION'] = GLOBUS_CONF['LOCATION']
    env['GLOBUS_TCP_PORT_RANGE'] = GLOBUS_CONF['TCP_PORT_RANGE']
    # env['GLOBUS_HOSTNAME'] = GLOBUS_CONF['HOSTNAME']

    if env.has_key('LD_LIBRARY_PATH'):        
        env['LD_LIBRARY_PATH'] = GLOBUS_CONF['LIB_PATH'] + ":" + env['LD_LIBRARY_PATH']
    else:
        env['LD_LIBRARY_PATH'] = GLOBUS_CONF['LIB_PATH']

    return env

def get_grid_path(machine, path):
    hostname = GRID_RESOURCE_TABLE[machine].get('hostname', machine)
    path = urllib.unquote(path)
    path = urllib.pathname2url(path)
    if not is_sanitized(path):
        raise ValueError("Bad Pathname")
    return "gsiftp://" + hostname + path

class GlobusHelper:
    GLOBUS_JOB_RUN_BIN = GLOBUS_CONF['LOCATION'] + "/bin/globus-job-run"

    @classmethod
    def get_globus_env(cls, user):
        return get_cred_env(user)

    def __init__(self, user):
        if not user.is_authenticated():
            raise Exception("User must be logged in")
        self.user = user
        self.env = self.get_globus_env(self.user)

    def run_job(self, command, host, flags=""):
        cmd_str = self.GLOBUS_JOB_RUN_BIN + " %s %s %s" % (host, flags, command)
        return run_command(cmd_str, env=self.env)