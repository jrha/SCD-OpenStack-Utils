#!/usr/bin/python
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



PARSER = argparse.ArgumentParser(description='Process some stuff.')
PARSER.add_argument('input', type=str, help='This is the json file to use')
PARSER.add_argument('--config', type=str, help='This is the config file to use')
PARSER.add_argument('--debug', action='store_true', help='This is the debug setting for the logger')
ARGS = PARSER.parse_args()

if ARGS.debug:
    LOG_LEVEL = logging.DEBUG
if not ARGS.debug:
    LOG_LEVEL = logging.INFO

logging.basicConfig(format='%(asctime)s | %(levelname)s : %(message)s',
level=LOG_LEVEL, datefmt='%d/%m/%Y | %I:%M:%S %p', filename='logging.log')
logging.info("PROGRAM STARTING")
CONFIGPARSER = SafeConfigParser()
# logging.basicConfig(, level=logging.info)
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

try:
    LDAPVAR = ldap.open(HOST)
except NameError, error:
    print("NameError ldap.open(HOST) failed")
    logging.critical("NameError ldap.open(HOST) failed")
    sys.exit(1)


ENV = os.environ.copy()


def cl(command):
    '''
    This is a function for command line scripts to be run
    '''
    pcommand = Popen(command, shell=True, stdout=PIPE, env=ENV)
    logging.info("running command: %s in cl function", command)
    return pcommand.communicate()[0]


def openstack_user_list(project):
    projectmembercmd = "openstack user list --project '{0}' -f json --noindent".format(project)
    # Loads project memebers from a json file
    logging.info("running command %s for grabbing a JSON file", projectmembercmd)
    return json.loads(cl(projectmembercmd))


def openstack_project_list():
    projectc = json.loads(cl("openstack project list -f json --noindent"))
    projectstring = [c["Name"] for c in projectc]
    return projectstring


def openstack_role_add(member, project, groups, i, projectmemberlist):
    macmd = "openstack role add --user '{0}' --user-domain stfc --project '{1}' --project-domain '{2}' '{3}'".format(member, project, DOMAIN, groups[i]["role"])
    logging.debug("Running %s for %s is not in %s", macmd, member, projectmemberlist)
    cl(macmd)


def openstack_project_create(description, project, projectstring):
    projectcreatecmd = "openstack project create --domain '{0}' --description '{1}' '{2}'".format(DOMAIN, description, project)
    logging.debug("running command: %s because %s is not in %s", projectcreatecmd, project, projectstring)
    cl(projectcreatecmd)


def ldap_flatusers(members):
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
        results = LDAPVAR.search(basedn, ldap.SCOPE_SUBTREE, msplitvar[0], props)
        result_type, result_data = LDAPVAR.result(results, 0)
        if result_type == ldap.RES_SEARCH_ENTRY and result_data != []:
            if 'member' in result_data[0][1]:
                mems = result_data[0][1]['member']
                memberstring = memberstring + ldap_flatusers(mems)
            else:  # is a user
                logging.debug("Appending %s to %s", result_data[0][1]['cn'][0], memberstring)
                memberstring.append(result_data[0][1]['cn'][0])
    logging.info("ldap_flatusers function ending")
    return memberstring


# Function for getting groups variable
def ldapgrabber(groups):
    '''
    This is the script that gets the information using ldap
    '''
    logging.info("ldapgrabber function starting")
    # Uses ldap.open to grab hostlist
    logging.info("opening HOST from config with ldap")
    LDAPVAR.protocol_version = ldap.VERSION3
    # Attempts to bind simple strings to the person.
    try:
        LDAPVAR.simple_bind_s(USER, PWD)
    except ldap.LDAPError, error:
        print error.message['desc']
    qurl = ["(|"] + ["(cn=%s)" % g for g in groups] + [")"]
    # Should be returning (|(cn= ))
    filt = "".join(qurl)
    # Sets attributes
    atrs = ["cn", "displayName", "member", "descripion"]
    try:
        results = LDAPVAR.search_st(BASEDN, ldap.SCOPE_SUBTREE, filt, atrs)
    except ldap.SERVER_DOWN:
        print(error.message['desc'])
        logging.critical(error.message['desc'])
        sys.exit(1)
    logging.info("ldapgrabber function ending")
    return results


    # Sets result to an empty dictionary
def getter(groups):
    '''
    This section is to sort through the json file it grabs from ldapgrabberself
    '''
    logging.info("Getter function starting")
    results = ldapgrabber(groups)
    result_set = {}
    for result_data in results:
        # Replaces " " with _20 which is ascii space and sets variables
        name = result_data[1]['displayName'][0]
        member = result_data[1]['member']
        role = groups[name]["role"]
        # print name
        # Sets an empty list
        resultdatalist = {}
        resultdatalist["members"] = ldap_flatusers(member)
        resultdatalist["description"] = name
        # Grabs a role and key from groups
        resultdatalist["role"] = role
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
    LDAPVAR.unbind_s()
    # print result_set
    # Returns result_set to putter
    logging.info("Getter function ending")
    return result_set


def putter(groups):
    '''
    This is the function to put the information gathered from getter
    into commands to run and use
    '''
    logging.info("putter function starting")
    logging.info("Loading JSON file from 'openstack project list -f json --noindent'")
    projectstring = openstack_project_list()

    for group in groups:
        members = groups[group]["members"]
        project = group
        # Sets a project to a profile is there is a linked project found
        if "project" in groups[group]:
            project = groups[group]["project"]
        description = groups[group]["description"]
        if project not in projectstring:
            # Run this command if there is no projectstring
            openstack_project_create(description, project, projectstring)
        # Command line to grab JSON file

        projectmemberlist = []
        # Iterates over projectmember list
        for user in openstack_user_list(project):
            logging.debug("adding %s to %s", user, projectmemberlist)
            # print j
            projectmemberlist.append(user["Name"])
        # Iterates over member list
        for member in members:
            if member not in projectmemberlist:
                openstack_role_add(member, project, groups, group, projectmemberlist)
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
            # Loads json file into commandline from sysargs
            logging.info("loading JSON file")
            groupdata = json.load(openfile)
            groupdata = {k.replace("_20", " "):v for k, v in groupdata.iteritems()}
            logging.debug("running putter(getter(groupdata))")
            putter(getter(groupdata))
    logging.info("PROGRAM ENDING")

if __name__ == "__main__":
    main()
