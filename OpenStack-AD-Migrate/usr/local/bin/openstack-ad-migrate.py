#!/usr/bin/python2
'''
This is a program
'''

import json
import sys
import os
import argparse
import logging
from subprocess import Popen, PIPE
from ConfigParser import SafeConfigParser, NoSectionError
import ldap
import ldap.sasl


LDAP_ATTRS = ["cn", "displayName", "member", "descripion"]


PARSER = argparse.ArgumentParser(description='Process some stuff.')
PARSER.add_argument('input', type=str, help='This is the json file to use')
PARSER.add_argument('--config', type=str, help='This is the config file to use')
PARSER.add_argument('--debug', action='store_true', help='This is the debug setting for the logger')
ARGS = PARSER.parse_args()

if ARGS.debug:
    LOG_LEVEL = logging.DEBUG
if not ARGS.debug:
    LOG_LEVEL = logging.INFO

logging.basicConfig(
    format='%(asctime)s | %(levelname)s : %(message)s',
    level=LOG_LEVEL,
    datefmt='%d/%m/%Y | %I:%M:%S %p',
    filename='logging.log',
)

logging.info("PROGRAM STARTING")
CONFIGPARSER = SafeConfigParser()
logging.info("Checking config file")

if ARGS.config:
    CONFIGPARSER.read(ARGS.config)
    logging.debug("commandline config file found")
if not ARGS.config:
    CONFIGPARSER.read('./etc/openstack-utils/config.ini')
    logging.info("non-commandline config file found")

logging.info("attempting to read config file")

try:
    USER = CONFIGPARSER.get('ad', 'userdn')
    PWD = CONFIGPARSER.get('ad', 'password')
    HOST = CONFIGPARSER.get('ad', 'host')
    BASEDN = CONFIGPARSER.get('ad', 'basedn')
    DOMAIN = CONFIGPARSER.get('openstack', 'domain')
except NoSectionError:
    logging.info("config file not found")
    # print("No config file")


ENV = os.environ.copy()


def cl(command):
    '''
    This is a function for command line scripts to be run
    '''
    pcommand = Popen(command, shell=True, stdout=PIPE, env=ENV)
    logging.info("running command: %s in cl function", command)
    return pcommand.communicate()[0]


def openstack_user_list(project):
    '''Get list of users for a project'''
    return json.loads(cl("openstack user list --project '{0}' -f json --noindent".format(project)))


def openstack_project_list():
    '''Get list of projects'''
    project_list = json.loads(cl("openstack project list -f json --noindent"))
    return [project["Name"] for project in project_list]


def openstack_role_add(username, project, role):
    '''Add a role (user) to a project'''
    cmd = "openstack role add --user '{0}' --user-domain stfc --project '{1}' --project-domain '{2}' '{3}'".format(
        username,
        project,
        DOMAIN,
        role,
    )
    cl(cmd)


def openstack_project_create(description, project):
    '''Create a project'''
    projectcreatecmd = "openstack project create --domain '{0}' --description '{1}' '{2}'".format(
        DOMAIN,
        description,
        project,
    )
    cl(projectcreatecmd)


def ldap_flatusers(members, ldap_session):
    '''
    This section is to add the results to a table for the program to use
    later on
    '''
    logging.info("ldap_flatusers function starting")
    memberstring = []
    for i in members:
        # splits msplitvar by ,
        msplitvar = i.split(",")
        basedn = BASEDN
        basedn = ",".join(msplitvar[1:])
        props = ["cn", "displayName", "member"]
        results = ldap_session.search(basedn, ldap.SCOPE_SUBTREE, msplitvar[0], props)
        result_type, result_data = ldap_session.result(results, 0)
        if result_type == ldap.RES_SEARCH_ENTRY and result_data != []:
            if 'member' in result_data[0][1]:
                mems = result_data[0][1]['member']
                memberstring = memberstring + ldap_flatusers(mems, ldap_session)
            else:  # is a user
                logging.debug("Appending %s to %s", result_data[0][1]['cn'][0], memberstring)
                memberstring.append(result_data[0][1]['cn'][0])
    logging.info("ldap_flatusers function ending")
    return memberstring


# Function for getting groups variable
def ldapgrabber(groups, ldap_session):
    '''
    This is the script that gets the information using ldap
    '''
    logging.info("ldapgrabber function starting")
    # Uses ldap.open to grab hostlist
    logging.info("opening HOST from config with ldap")

    # Bind to LDAP server
    try:
        ldap_session.simple_bind_s(USER, PWD)
    except ldap.LDAPError, error:
        print error.message['desc']

    filt = "(|%s)" % "".join(["(cn=%s)" % g for g in groups])
    # Sets attributes

    try:
        results = ldap_session.search_st(BASEDN, ldap.SCOPE_SUBTREE, filt, LDAP_ATTRS)
    except ldap.SERVER_DOWN:
        print(error.message['desc'])
        logging.critical(error.message['desc'])
        sys.exit(1)
    logging.info("ldapgrabber function ending")
    return results


def getter(groups, ldap_session):
    '''
    This section is to sort through the json file it grabs from ldapgrabberself
    '''
    logging.info("Getter function starting")
    results = ldapgrabber(groups, ldap_session)
    result_set = {}

    for result_data in results:
        # Replaces " " with _20 which is ascii space and sets variables
        name = result_data[1]['displayName'][0]
        member = result_data[1]['member']
        role = groups[name]["role"]

        resultdatalist = {
            "members" : ldap_flatusers(member, ldap_session),
            "description" : name,
            "role" : role,
        }

        # if a project name is specified then use it
        if "project" in groups[name]:
            resultdatalist["project"] = groups[name]["project"]

        # If description is in result_data then it
        # Grabs the description from the result_data
        if "description" in result_data:
            resultdatalist["description"] = result_data[1]['description'][0]

        # Sets the name of the results to result_set[name]
        result_set[name] = resultdatalist
        logging.debug("info result_set[name] to resultdatalist %s", result_set[name])

    logging.info("Getter function ending")
    return result_set


def putter(groups):
    '''
    This is the function to put the information gathered from getter
    into commands to run and use
    '''
    logging.info("putter function starting")
    logging.info("Loading JSON file from 'openstack project list -f json --noindent'")
    project_list = openstack_project_list()

    for group, group_info in groups.iteritems():
        ldap_user_list = group_info["members"]
        role = group_info["role"]

        # Override project name if specified
        if "project" in group_info:
            group = group_info["project"]

        description = group_info["description"]

        if group not in project_list:
            logging.debug("%s is not in %s, adding", group, project_list)
            openstack_project_create(description, group)

        project_user_list = [user['Name'] for user in openstack_user_list(group)]

        for user in ldap_user_list:
            if user not in project_user_list:
                logging.debug("%s is not in %s, adding", user, project_user_list)
                openstack_role_add(user, group, role)

    logging.info("putter function ending")


def main():
    '''
    This is the main function that causes the others to be called
    '''
    # Sys exit 1 if not enough args

    if not ARGS.input:
        print "Usage: {0} <groups-file>".format(sys.argv[0])
        logging.critical("groups file not supplied")
        sys.exit(1)
    if ARGS.input:
        with open(sys.argv[1]) as openfile:
            # Load json group file
            logging.info("loading JSON group file")
            groupdata = json.load(openfile)
            groupdata = {k.replace("_20", " "):v for k, v in groupdata.iteritems()}

            # Connect to LDAP server
            try:
                ldap_session = ldap.open(HOST)
            except NameError, error:
                print("NameError ldap.open(HOST) failed")
                logging.critical("NameError ldap.open(HOST) failed")
                sys.exit(1)
            ldap_session.protocol_version = ldap.VERSION3

            # The real meat
            logging.debug("running putter(getter(...))")
            putter(getter(groupdata, ldap_session))

            # Disconnect from LDAP server
            ldap_session.unbind_s()

    logging.info("PROGRAM ENDING")


if __name__ == "__main__":
    main()
