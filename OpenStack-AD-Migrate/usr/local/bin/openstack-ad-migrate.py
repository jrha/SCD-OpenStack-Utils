#!/usr/bin/python
import ldap
import ldap.sasl
import json
import sys
import os
from subprocess import Popen, PIPE
from ConfigParser import SafeConfigParser

configparser = SafeConfigParser()


# Section grabs config
#try:
if True:
    configparser.read('./etc/openstack-utils/config.ini')
    user = configparser.get('ad', 'userdn')
    pwd = configparser.get('ad', 'password')
    host = configparser.get('ad', 'host')
    basedn = configparser.get('ad', 'basedn')
    domain = configparser.get('openstack', 'domain')
# Section grabs config - Close
# Exception
# except:
#         print 'Unable to read from config file'
#         sys.exit(1)
# Close Exception

env = os.environ.copy()


# Use command in commandline usage: cl(commandvariable)
def cl(c):
    p = Popen(c, shell=True, stdout=PIPE, env=env)
    print c
    return p.communicate()[0]
# Closing cl definition


def ldap_flatusers(members, ld):
    ms = []
    for m in members:
        # splits var s by ,
        s = m.split(",")

        basedn = ",".join(s[1:])
        filt = s[0]
        props = ["cn", "displayName", "member"]
        results = ld.search(basedn, ldap.SCOPE_SUBTREE, filt, props)

        while 1:
            result_type, result_data = ld.result(results, 0)
            if(result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    if 'member' in result_data[0][1]:
                        mems = result_data[0][1]['member']
                        ms = ms + ldap_flatusers(mems, ld)
                    else:  # is a user
                        ms.append(result_data[0][1]['cn'][0])
    return ms

# Function for getting groups variable
def getter(groups):
    # Uses ldap.open to grab hostlist
    ld = ldap.open(host)
    ld.protocol_version = ldap.VERSION3
    # Attempts to bind simple strings to the person.
    try:
        ld.simple_bind_s(user, pwd)
    except ldap.LDAPError, e:
        print e

    qurl = ["(|"] + ["(cn="+g.replace("_20", " ") + ")" for g in groups] + [")"]
    # Should be returning (|(cn= ))
    filt = "".join(qurl)
    # Sets attributes
    atrs = ["cn", "displayName", "member", "descripion"]

    results = ld.search(basedn, ldap.SCOPE_SUBTREE, filt, atrs)

    result_set = {}
    # Sets result to an empty dictionary
    while 1:
        result_type, result_data = ld.result(results, 0)
        if(result_data == []):
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                name = result_data[0][1]['displayName'][0]

                # Replaces " " with _20 which is ascii space
                key = result_data[0][1]['displayName'][0].replace(" ", "_20")

                print name

                # Sets an empty list
                d = {}
                d["members"] = ldap_flatusers(result_data[0][1]['member'], ld)
                d["description"] = name
                # Grabs a role and key from groups
                d["role"] = groups[key]["role"]

                # if groups[key] is true then it grabs
                # project from groups[key]['project']
                if "project" in groups[key].keys():
                    d["project"] = groups[key]["project"]

                # If description is in result_data then it
                # Grabs the description from the result_data
                if "description" in result_data:
                    d["description"] = result_data[0][1]['description'][0]

                # Sets the name of the reusults to d
                result_set[name] = d
                # result_set.append(d)
    ld.unbind_s()

    # Prints what was resulted from the while 1: loop
    print result_set
    # for group in groups.keys():
    #       print group
    #       groups[group]["members"] = result_set[group]["mems"]
    # print groups

    # Returns result_set to putter
    return result_set


def putter(groups):

    # Sets command to variable and runs command using cl
    # also loads json file.
    projectcmd = "openstack project list -f json --noindent"
    projectcj = cl(projectcmd)
    projectc = json.loads(projectcj)

    projectstring = [c["Name"] for c in projectc]

    for g in groups.keys():
        members = groups[g]["members"]
        name = g
        project = name
        # Sets a project to a profile is there is a linked project found
        if "project" in groups[name].keys():
            project = groups[g]["project"]
        role = groups[g]["role"]
        description = groups[g]["description"]

        if project not in projectstring:
            # Run this command if there is no projectstring
            projectcreatecmd = "openstack project create --domain '{0}' --description '{1}' '{2}'".format(domain,description, project)
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

        projectmemberstring = [c["Name"] for c in projectmemberc]
        # Print current members and project members
        print "members"
        print members
        print "projectmembers"
        print projectmemberc
        # Iterates over member list
        for member in members:
            if member not in projectmemberlist:
                macmd = "openstack role add --user '{0}' --user-domain stfc --project '{1}' --project-domain '{2}' '{3}'".format(member, project, domain, role)
                cl(macmd)


if __name__ == "__main__":
    # Sys exit 1 if not enough args
    if len(sys.argv) < 2:
        print "Usage: {0} <groups-file>".format(sys.argv[0])
        sys.exit(1)
    else:
        with open(sys.argv[1]) as f:
            # fl = f.read().split("\n")[:-1]

            # Loads json file into commandline from sysargs
            groupdata = json.load(f)
            print groupdata
            # Runs the groupdata loaded through getter
            groupdata = getter(groupdata)
            # Runs output from getter through putter
            # Current command is putter(getter(groupdata))
            putter(groupdata)
