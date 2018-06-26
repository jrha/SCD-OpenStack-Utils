#!/usr/bin/python
'''
This is a program
'''
import ldap
import ldap.sasl
import json
import sys
import os
from subprocess import Popen, PIPE
from ConfigParser import SafeConfigParser

CONFIGPARSER = SafeConfigParser()


# Section grabs config
#try:
if True:
    CONFIGPARSER.read('./etc/openstack-utils/config.ini')
    USER = CONFIGPARSER.get('ad', 'userdn')
    PWD = CONFIGPARSER.get('ad', 'password')
    HOST = CONFIGPARSER.get('ad', 'host')
    BADESN = CONFIGPARSER.get('ad', 'basedn')
    DOMAIN = CONFIGPARSER.get('openstack', 'domain')
# Section grabs config - Close
# Exception
# except:
#         print 'Unable to read from config file'
#         sys.exit(1)
# Close Exception

ENV = os.environ.copy()


# Use command in commandline usage: cl(commandvariable)
def cl(command):
    '''
    This is a command line function
    '''
    pcommand = Popen(command, shell=True, stdout=PIPE, env=ENV)
    print command
    return pcommand.communicate()[0]
# Closing cl definition


def ldap_flatusers(members, ldapvar):
    '''
    This section is to add the results to the table
    '''
    memberstring = []
    for i in members:
        # splits var s by ,
        msplitvar = i.split(",")

        basedn = ",".join(msplitvar[1:])
        filt = msplitvar[0]
        props = ["cn", "displayName", "member"]
        results = ldapvar.search(basedn, ldap.SCOPE_SUBTREE, filt, props)

        result_type, result_data = ldapvar.result(results, 0)
        if result_data != []:
            if result_type == ldap.RES_SEARCH_ENTRY:
                if 'member' in result_data[0][1]:
                    mems = result_data[0][1]['member']
                    memberstring = memberstring + ldap_flatusers(mems, ldapvar)
                else:  # is a user
                    memberstring.append(result_data[0][1]['cn'][0])
    return memberstring

# Function for getting groups variable
def getter(groups):
    '''
    This is the script that gets the information
    '''
    # Uses ldap.open to grab hostlist
    ldapvar = ldap.open(HOST)
    ldapvar.protocol_version = ldap.VERSION3
    # Attempts to bind simple strings to the person.
    try:
        ldapvar.simple_bind_s(USER, PWD)
    except ldap.LDAPError, error:
        print error

    qurl = ["(|"] + ["(cn="+g.replace("_20", " ") + ")" for g in groups] + [")"]
    # Should be returning (|(cn= ))
    filt = "".join(qurl)
    # Sets attributes
    atrs = ["cn", "displayName", "member", "descripion"]

    results = ldapvar.search(BADESN, ldap.SCOPE_SUBTREE, filt, atrs)

    result_set = {}
    # Sets result to an empty dictionary
    while 1:
        result_type, result_data = ldapvar.result(results, 0)
        if result_data == []:
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                name = result_data[0][1]['displayName'][0]

                # Replaces " " with _20 which is ascii space
                key = result_data[0][1]['displayName'][0].replace(" ", "_20")

                print name

                # Sets an empty list
                resultdatalist = {}
                resultdatalist["members"] = ldap_flatusers(result_data[0][1]['member'], ldapvar)
                resultdatalist["description"] = name
                # Grabs a role and key from groups
                resultdatalist["role"] = groups[key]["role"]

                # if groups[key] is true then it grabs
                # project from groups[key]['project']
                if "project" in groups[key].keys():
                    resultdatalist["project"] = groups[key]["project"]

                # If description is in result_data then it
                # Grabs the description from the result_data
                if "description" in result_data:
                    resultdatalist["description"] = result_data[0][1]['description'][0]

                # Sets the name of the reusults to d
                result_set[name] = resultdatalist
                # result_set.append(d)
    ldapvar.unbind_s()

    # Prints what was resulted from the while 1: loop
    print result_set
    # for group in groups.keys():
    #       print group
    #       groups[group]["members"] = result_set[group]["mems"]
    # print groups

    # Returns result_set to putter
    return result_set


def putter(groups):
    '''
    This is the function to put the information together in one
    '''

    # Sets command to variable and runs command using cl
    # also loads json file.
    projectcmd = "openstack project list -f json --noindent"
    projectcj = cl(projectcmd)
    projectc = json.loads(projectcj)

    projectstring = [c["Name"] for c in projectc]

    for i in groups.keys():
        members = groups[i]["members"]
        name = i
        project = name
        # Sets a project to a profile is there is a linked project found
        if "project" in groups[name].keys():
            project = groups[i]["project"]
        role = groups[i]["role"]
        description = groups[i]["description"]

        if project not in projectstring:
            # Run this command if there is no projectstring
            projectcreatecmd = "openstack project create --domain '{0}' --description '{1}' '{2}'".format(DOMAIN, description, project)
            cl(projectcreatecmd)

        # Command line to grab JSON file
        projectmembercmd = "openstack user list --project '{0}' -f json --noindent".format(project)

        # Command line to get a json file's location into a singular variable
        projectmemberjson = cl(projectmembercmd)

        # Loads project memebers from a json file
        projectmemberc = json.loads(projectmemberjson)
        projectmemberlist = []
        # Iterates over projectmember list
        for projectmember in projectmemberc:
            print projectmember
            projectmemberlist.append(projectmember["Name"])

        #unused?
        projectmemberstring = [c["Name"] for c in projectmemberc]
        # Print current members and project members
        print "members"
        print members
        print "projectmembers"
        print projectmemberc
        # Iterates over member list
        for member in members:
            if member not in projectmemberlist:
                macmd = "openstack role add --user '{0}' --user-domain stfc --project '{1}' --project-domain '{2}' '{3}'".format(member, project, DOMAIN, role)
                cl(macmd)

def main():
    '''
    This is the main function that causes the others to be called
    '''
    # Sys exit 1 if not enough args
    if len(sys.argv) < 2:
        print "Usage: {0} <groups-file>".format(sys.argv[0])
        sys.exit(1)
    else:
        with open(sys.argv[1]) as openfile:
            # fl = f.read().split("\n")[:-1]

            # Loads json file into commandline from sysargs
            groupdata = json.load(openfile)
            print groupdata
            # Runs the groupdata loaded through getter
            groupdata = getter(groupdata)
            # Runs output from getter through putter
            # Current command is putter(getter(groupdata))
            putter(groupdata)


if __name__ == "__main__":
    main()
