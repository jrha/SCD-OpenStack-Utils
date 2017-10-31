import logging
import requests
import common
import subprocess

from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from requests_kerberos import HTTPKerberosAuth

prefix="vm-openstack-dev-"
model="vm-openstack"
MAKE_SUFFIX = "/host/{0}/command/make"
MANAGE_SUFFIX = "/host/{0}/command/manage?hostname={0}&{1}={2}&force=true"
HOST_CHECK_SUFFIX = "/host/{0}"
CREATE_MACHINE_SUFFIX = "/next_machine/{0}?model={1}&serial={2}&vmhost={3}&cpucount={4}&memory={5}"
ADD_INTERFACE_SUFFIX = "/machine/{0}/interface/{1}?mac={2}"
UPDATE_INTERFACE_SUFFIX = "/machine/{0}/interface/{1}?boot&default_route"
ADD_INTERFACE_ADDRESS_SUFFIX = "/machine/{0}/interface/{1}/address?ip={2}&fqdn={3}"
ADD_HOST_SUFFIX="/host/{0}?machine={1}&ip={2}&archetype={3}&domain={4}&personality={5}&osname={6}&osversion={7}"
DELETE_HOST_SUFFIX="/host/{0}"
DELETE_MACHINE_SUFFIX="/machine/{0}"

logger = logging.getLogger(__name__)


def verify_kerberos_ticket():
    logger.info("Checking for valid Kerberos Ticket")

    if subprocess.call(['klist', '-s']) == 1:
        logger.warn("No ticket found / expired. Obtaining new one")
        kinit_cmd = ['kinit', '-k']

        if common.config.get("kerberos", "suffix") != "":
            kinit_cmd.append(common.config.get("kerberos", "suffix"))

        subprocess.call(kinit_cmd)

        if subprocess.call(['klist', '-s']) == 1:
            raise Exception("Failed to obtain valid Kerberos ticket")

    logger.info("Kerberos ticket success")
    return True


def aq_make(hostname, personality=None, osversion=None, archetype=None, osname=None):
    logger.info("Attempting to make templates for " + hostname)

    # strip out blank parameters and hostname
    params = {k: v for k, v in locals().items() if v is not None and k != "hostname"}

    # join remaining parameters to form url string
    params = [k + "=" + v for k, v in params.items()]

    url = common.config.get("aquilon", "url") + MAKE_SUFFIX.format(hostname) + "?" + "&".join(params)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.post(url, auth=HTTPKerberosAuth())

    if response.status_code != 200:
        logger.error("Aquilon make failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon make failed")

    logger.info("Successfully made templates")


def aq_manage(hostname, env_type, env_name):
    logger.info("Attempting to manage %s to %s %s" % (hostname, env_type, env_name))

    url = common.config.get("aquilon", "url") + MANAGE_SUFFIX.format(hostname, env_type, env_name)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.post(url, auth=HTTPKerberosAuth())

    if response.status_code != 200:
        logger.error("Aquilon manage failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon manage failed")

    logger.info("Successfully managed machine")

def machine_create(uuid,vmhost,vcpus,memory,hostname):
    logger.info("Attempting to create machine for %s " % (hostname))

    url = common.config.get("aquilon", "url") + CREATE_MACHINE_SUFFIX.format(prefix,model,uuid,vmhost,vcpus,memory)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.put(url, auth=HTTPKerberosAuth())
    machinename = response.text
    if response.status_code != 200:
        logger.error("Aquilon create machine failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon machine create failed")

    logger.info("Successfully created machine")
    return machinename

def machine_delete(machinename):
    logger.info("Attempting to delete machine for %s " % (machinename))

    url = common.config.get("aquilon", "url") + DELETE_MACHINE_SUFFIX.format(machinename)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.delete(url, auth=HTTPKerberosAuth())
    machinename = response.text
    if response.status_code != 200:
        logger.error("Aquilon delete machine failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon machine delete failed")

    logger.info("Successfully deleted machine")


def host_create(hostname, machinename,firstip,archetype,domain,personality,osname,osversion):
    logger.info("Attempting to create host for %s " % (hostname))

    url = common.config.get("aquilon", "url") + ADD_HOST_SUFFIX.format(hostname,machinename,firstip,archetype,domain,personality,osname,osversion)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.put(url, auth=HTTPKerberosAuth())
    if response.status_code != 200:
        logger.error("Aquilon create host failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon host create failed")

    logger.info("Successfully created host")

def host_delete(hostname):
    logger.info("Attempting to delete host for %s " % (hostname))

    url = common.config.get("aquilon", "url") + DELETE_HOST_SUFFIX.format(hostname)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.delete(url, auth=HTTPKerberosAuth())
    if response.status_code != 200:
        logger.error("Aquilon delete host failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon host delete failed")

    logger.info("Successfully deleted host")



def add_machine_interface(machinename,ipaddr,macaddr,label,interfacename,hostname):
    logger.info("Attempting to add ip %s to machine %s " % (ipaddr,machinename))

    url = common.config.get("aquilon", "url") + ADD_INTERFACE_SUFFIX.format(machinename,interfacename,macaddr)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.put(url, auth=HTTPKerberosAuth())
    if response.status_code != 200:
        logger.error("Aquilon add interface failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon add interface failed")
def add_machine_interface_address(machinename,ipaddr,macaddr,label,interfacename,hostname):
    logger.info("Attempting to add address ip %s to machine %s " % (ipaddr,machinename))

    url = common.config.get("aquilon", "url") + ADD_INTERFACE_ADDRESS_SUFFIX.format(machinename,interfacename,ipaddr,hostname)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.put(url, auth=HTTPKerberosAuth())
    if response.status_code != 200:
        logger.error("Aquilon add interface address failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon add interface address failed")

    logger.info("Successfully added interface")

def update_machine_interface(machinename,interfacename):
    logger.info("Attempting to bootable %s " % (machinename))

    url = common.config.get("aquilon", "url") + UPDATE_INTERFACE_SUFFIX.format(machinename,interfacename)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.post(url, auth=HTTPKerberosAuth())
    if response.status_code != 200:
        logger.error("Aquilon bootable interface failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon bootable interface failed")

def vm_create(hostname, domain=None, sandbox=None, personality=None, osversion=None, archetype=None, osname=None):


    if domain:
        aq_manage(hostname, "domain", domain)
    else:
        aq_manage(hostname, "sandbox", sandbox)

    aq_make(hostname, personality, osversion, archetype, osname)


def vm_delete(hostname,machinename):
    #try:
    #    delete_host(hostname)
    #except Exception as e:
    #    raise Exception("Aquilon delete host failed")

    try:
        delete_machine(machinename)
    except Exception as e:
        raise Exception("Aquilon delete machine failed")
    # manage the host back to prod
    try:
        aq_manage(hostname, "domain", "prod_cloud")
    except Exception as e:
        raise Exception("Aquilon reset env failed")
 

    # reset personality etc ...
    try:
        aq_make(hostname, "nubesvms", "6x-x86_64", "ral-tier1", "sl")
    except Exception as e:
        raise Exception("Aquilon reset personalit etc failed")

    


def check_host_exists(hostname):
    logger.info("Attempting to make templates for " + hostname)

    url = common.config.get("aquilon", "url") + HOST_CHECK_SUFFIX.format(hostname)

    verify_kerberos_ticket()

    s = requests.Session()
    s.verify = "/etc/grid-security/certificates/"
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[503])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.get(url, auth=HTTPKerberosAuth())

    if response.status_code != 200:
        logger.error("Aquilon host check failed: " + str(response.text))
        logger.error(url)
        raise Exception("Aquilon make failed")

    logger.info("Successfully made templates")

