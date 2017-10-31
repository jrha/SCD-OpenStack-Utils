import sys
import pika
import json
import socket
import logging

import common
import openstack_api
import aq_api

logger = logging.getLogger(__name__)


def is_aq_message(message):
    """
    Check to see if the metadata in the message contains entries that suggest it
    is for an Aquilon VM.
    """
    metadata = message.get("payload").get("metadata")
    print(metadata)
    if metadata:
        if set(metadata.keys()).intersection(['AQ_DOMAIN', 'AQ_SANDBOX', 'AQ_OSVERSION', 'AQ_PERSONALITY', 'AQ_ARCHETYPE', 'AQ_OS']):
            return True
    if metadata:
        if set(metadata.keys()).intersection(['aq_domain', 'aq_sandbox', 'aq_osversion', 'aq_personality', 'aq_archetype', 'aq_os']):
            return True
    metadata = message.get("payload").get("image_meta")
    print(metadata)
    if metadata:
        if set(metadata.keys()).intersection(['AQ_DOMAIN', 'AQ_SANDBOX', 'AQ_OSVERSION', 'AQ_PERSONALITY', 'AQ_ARCHETYPE', 'AQ_OS']):
            return True
    if metadata:
        if set(metadata.keys()).intersection(['aq_domain', 'aq_sandbox', 'aq_osversion', 'aq_personality', 'aq_archetype', 'aq_os']):
            return True
   
    return False

def get_AQ_value(message,key):
    returnstring = None
    returnstring = message.get("payload").get("metadata").get(key)
    if (returnstring == None):
        returnstring = message.get("payload").get("image_meta").get(key)
        if (returnstring == None):
            returnstring = message.get("payload").get("metadata").get(key.lower())
            if (returnstring == None):
                returnstring = message.get("payload").get("image_meta").get(key.lower())
    return returnstring


def consume(message):
    event = message.get("event_type")
 #   print (event)
    if event == "compute.instance.create.end":
#        print (message)
        if is_aq_message(message):
            print("=== Received Aquilon VM create message ===")
            logger.info("=== Received Aquilon VM create message ===")

            project_name = message.get("_context_project_name")
            project_id = message.get("_context_project_id")
            vm_id = message.get("payload").get("instance_id")
            vm_name = message.get("payload").get("display_name")
            username = message.get("_context_user_name")

            # convert VM ip address(es) into hostnames
            hostnames = []
            for ip in message.get("payload").get("fixed_ips"):
                try:
                    hostname = socket.gethostbyaddr(ip.get("address"))[0]
                    hostnames.append(hostname)
            #        aq_api.check_host_exists(hostname)
                    
                except Exception as e:
                    logger.error("Problem converting ip to hostname" + str(e))
                    raise Exception("Problem converting ip to hostname")

            if len(hostnames) > 1:
                logger.warn("There are multiple hostnames assigned to this VM")

            logger.info("Project Name: %s (%s)" % (project_name, project_id))
            logger.info("VM Name: %s (%s) " % (vm_name, vm_id))
            logger.info("Username: " + username)
            logger.info("Hostnames: " + ', '.join(hostnames))

            try:
                # add hostname(s) to metadata for use when capturing delete messages
                # as these messages do not contain ip information
                openstack_api.update_metadata(project_id, vm_id, {"HOSTNAMES" : ', '.join(hostnames)})
            except Exception as e:
                logger.error("Failed to update metadata: " + str(e))
                raise Exception("Failed to update metadata")

            print (message.get("payload"))
            domain = get_AQ_value(message,"AQ_DOMAIN")
            sandbox =   get_AQ_value(message,"AQ_SANDBOX")
            personality =  get_AQ_value(message,"AQ_PERSONALITY")
            osversion =  get_AQ_value(message,"AQ_OSVERSION")
            archetype =  get_AQ_value(message,"AQ_ARCHETYPE")
            osname =  get_AQ_value(message,"AQ_OSNAME")
            
            vcpus = message.get("payload").get("vcpus")
            root_gb = message.get("payload").get("root_gb")
            memory_mb = message.get("payload").get("memory_mb")
            uuid = message.get("payload").get("instance_id")
            vmhost = message.get("payload").get("host")
            firstip = message.get("payload").get("fixed_ips")[0].get("address")

            print("########################   create new machine #######################")
            try:
                machinename = aq_api.machine_create(uuid,vmhost,vcpus,memory_mb,hostname)
            except Exception as e:
                raise Exception("Failed to create machine")
            openstack_api.update_metadata(project_id, vm_id, {"AQ_MACHINENAME" : machinename})

            for index,ip in enumerate(message.get("payload").get("fixed_ips")):
                interfacename = "eth"+ str(index)
                try:
                    aq_api.add_machine_interface(machinename,ip.get("address"),ip.get("vif_mac"),ip.get("label"),interfacename, socket.gethostbyaddr(ip.get("address"))[0])
                except Exception as e:
                    raise Exception("Failed to add machine interface")
            try:
                aq_api.update_machine_interface(machinename,"eth0")
            except Exception as e:
                raise Exception("Failed to set default interface")
            try:
                aq_api.host_create(hostnames[0],machinename,firstip,archetype,domain,personality,osname,osversion)
            except Exception as e:
                raise Exception("Failed to create host")
            for index,ip in enumerate(message.get("payload").get("fixed_ips")):
                interfacename = "eth"+ str(index)
                try:
                    aq_api.add_machine_interface_address(machinename,ip.get("address"),ip.get("vif_mac"),ip.get("label"),interfacename, socket.gethostbyaddr(ip.get("address"))[0])
                except Exception as e:
                    raise Exception("Failed to add machine interface address")

            print("Domain: %s" % domain)
            print("Sandbox: %s" % sandbox)
            print("Personality: %s" % personality)
            print("OS Version: %s" % osversion)
            print("Archetype: %s" % archetype)
            print("OS Name: %s" % osname)

            logger.info("Domain: %s" % domain)
            logger.info("Sandbox: %s" % sandbox)
            logger.info("Personality: %s" % personality)
            logger.info("OS Version: %s" % osversion)
            logger.info("Archetype: %s" % archetype)
            logger.info("OS Name: %s" % osname)

            # as the machine may have been assigned more that one ip address,
            # apply the aquilon configuration to all of them
            for host in hostnames:
                    
                try:
                    if domain:
                        aq_manage(hostname, "domain", domain)
                    else:
                        aq_manage(hostname, "sandbox", sandbox)
                except Exception as e:
                    logger.error("Failed to manage in Aquilon: " + str(e))
                    openstack_api.update_metadata(project_id, vm_id, {"AQ_STATUS" : "FAILED"})
                    raise Exception("Failed to set Aquilon configuration")
                try:
                    aq_make(hostname, personality, osversion, archetype, osname)
                except Exception as e:
                    logger.error("Failed to make in Aquilon: " + str(e))
                    openstack_api.update_metadata(project_id, vm_id, {"AQ_STATUS" : "FAILED"})
                    raise Exception("Failed to set Aquilon configuration")


            logger.info("Successfully applied Aquilon configuration")
            openstack_api.update_metadata(project_id, vm_id, {"AQ_STATUS" : "SUCCESS"})

            logger.info("=== Finished Aquilon creation hook for VM " + vm_name + " ===")


    if event == "compute.instance.delete.start":
        print (message)
        if is_aq_message(message):
            logger.info("=== Received Aquilon VM delete message ===")

            project_name = message.get("_context_project_name")
            project_id = message.get("_context_project_id")
            vm_id = message.get("payload").get("instance_id")
            vm_name = message.get("payload").get("display_name")
            username = message.get("_context_user_name")
            metadata = message.get("payload").get("metadata")
            machinename = message.get("payload").get("metadata").get("AQ_MACHINENAME")

            logger.info("Project Name: %s (%s)" % (project_name, project_id))
            logger.info("VM Name: %s (%s) " % (vm_name, vm_id))
            logger.info("Username: " + username)
            logger.info("Hostnames: %s" % metadata.get('HOSTNAMES'))
            for host in metadata.get("HOSTNAMES").split(","):
                try:
                    aq_api.host_delete(host)
                except Exception as e:
                    logger.error("Failed to delete host: " + str(e))
                    openstack_api.update_metadata(project_id, vm_id, {"AQ_STATUS" : "FAILED"})
                    raise Exception("Failed to delete host")
                   
            try:
                aq_api.machine_delete(machinename)
            except Exception as e:
                raise Exception("Failed to delete machine")

            try:
                for host in metadata.get('HOSTNAMES').split(','):
                    aq_api.vm_delete(host,machinename)
            except Exception as e:
                logger.error("Failed to reset Aquilon configuration: " + str(e))
                openstack_api.update_metadata(project_id, vm_id, {"AQ_STATUS" : "FAILED"})
                raise Exception("Failed to reset Aquilon configuration")

            logger.info("Successfully reset Aquilon configuration")
            logger.info("=== Finished Aquilon deletion hook for VM " + vm_name + " ===")


def on_message(channel, method, header, raw_body):
    body = json.loads(raw_body.decode("utf-8"))
    message = json.loads(body["oslo.message"])

    try:
        consume(message)
    except Exception as e:
        logger.error("Something went wrong parsing the message: " + str(e))
        logger.error(str(message))

    # remove the message from the queue
    channel.basic_ack(delivery_tag=method.delivery_tag)


def initiate_consumer():
    logger.info("Initiating message consumer")

    host = common.config.get("rabbit", "host")
    port = common.config.getint("rabbit", "port")
    login_user = common.config.get("rabbit", "login_user")
    login_pass = common.config.get("rabbit", "login_pass")
    exchanges = common.config.get("rabbit", "exchanges").split(",")

    credentials = pika.PlainCredentials(login_user, login_pass)
    parameters = pika.ConnectionParameters(host, port, "/", credentials,
                                           connection_attempts=10,
                                           retry_delay=2)

    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.queue_declare("ral.info")

    for exchange in exchanges:
        channel.queue_bind("ral.info", exchange, "ral.info")

    channel.basic_consume(on_message, "ral.info")
    
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
        connection.close()
        sys.exit(0)
    except Exception as e:
        logger.error("Something went wrong with the pika message consumer " + str(e))
        connection.close()
        raise e
