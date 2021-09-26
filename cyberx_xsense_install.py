#!/usr/bin/env python

from cyberx.install import InstallComponent
from cyberx import common
from cyberx import components as components_utils
from cyberx import process
from time import sleep
import os
import shutil
import sys
import uuid
import random
import string
import json
from random import randint
import tempfile
import tarfile


logger = common.create_logger()


# class Horizon(InstallComponent):
#     def __init__(self, is_upgrade):
#         super(self.__class__, self).__init__('Horizon Config')
#         self.is_upgrade = is_upgrade

#     def _install(self):
#         logger.debug('Load horizon configuration...')
#         cmd = '/var/cyberx/horizon/init/load-horizon-config --no-db'

#         process.run(cmd, raise_on_failure=True)


# ---------------------
# ---------------------
# ---------------------


# class Docker(InstallComponent):
#     def __init__(self):
#         super(self.__class__, self).__init__('Docker')

#     def _install(self):
#         self.set_docker_permissions()
#         self.restart_docker_daemon()

#     def set_docker_permissions(self):
#         logger.info("Running \'usermod -aG docker cyberx\'")
#         process.run("usermod -aG docker cyberx")
#         logger.info("Running \'usermod -aG docker www-data\'")
#         process.run("usermod -aG docker www-data")

#     def restart_docker_daemon(self):
#         logger.info("Restarting docker daemon")
#         process.run("sudo systemctl restart docker")


class HorizonService(InstallComponent):
    def __init__(self, container_name, image_name, component_name):
        super(HorizonService, self).__init__(component_name)
        self.container_name = container_name
        self.image_name = image_name

    def init_container(self, main_log, stats_log, plugins_dir, properties_file_name):
        logger.info('Creating log files for Horizon Service container name {}'.format(self.container_name))
        open(main_log, 'a').close()
        open(stats_log, 'a').close()

        logger.info("Starting \'{}\' container".format(self.container_name))
        process.run(
            '/usr/bin/docker run'
            ' --mount "type=bind,src={main_log},dst=/var/cyberx/logs/horizon.log"'
            ' --mount "type=bind,src={stats_log},dst=/var/cyberx/logs/horizon.stats.log"'
            ' --mount "type=bind,src={plugins_dir},dst=/opt/horizon/custom_dissectors"'
            ' --mount "type=bind,src=/var/cyberx/properties/network.properties,dst=/opt/horizon/etc/network.properties"'
            ' --mount "type=bind,src={properties},dst=/opt/horizon/etc/horizon.properties"'
            ' --mount "type=bind,src=/opt/fuzzer,dst=/tmp/fuzzer"'
            ' --network host'
            ' --privileged'
            ' -d'
            ' --name {container_name} {image_name}'.format(main_log=main_log,
                                                           stats_log=stats_log,
                                                           plugins_dir=plugins_dir,
                                                           properties=properties_file_name,
                                                           container_name=self.container_name,
                                                           image_name=self.image_name),
            raise_on_failure=True)

    def extract_infrastructure_plugins_from_horizon_docker(self):
        try:
            dst = "/var/cyberx/horizon_dissectors/"
            src = "/opt/horizon/lib/horizon/"
            logger.info("Starting copy files from \'{}\' container to {} ".format(self.container_name, dst))

            files = {"ethernet", "tcp", "udp", "vlan", "ipv4", "ipv4flow", "ipv4fragment", "ethernet_type", "llc"}
            for infra_file in files:
                file_path = src + infra_file
                process.run('sudo docker cp {}:{} {}'.format(
                    self.container_name, file_path, dst), raise_on_failure=True)
        except Exception as ex:
            logger.error("Failed to copy files from {} to {}".format(self.container_name, dst))
            logger.error(ex)


class TrafficMonitorService(HorizonService):
    def __init__(self, image_name):
        super(self.__class__, self).__init__('traffic-monitor', image_name, 'Traffic Monitor Service')

    def _install(self):
        super(self.__class__, self).init_container(
            '/var/cyberx/logs/traffic-monitor-parser.log',
            '/var/cyberx/logs/traffic-monitor.stats.log',
            '/var/cyberx/traffic_monitor_dissectors',
            '/var/cyberx/properties/traffic-monitor.properties'
        )


class HorizonParserService(HorizonService):
    def __init__(self, image_name):
        super(self.__class__, self).__init__('horizon-parser', image_name, 'Horizon Parser Service')

    def _install(self):
        super(self.__class__, self).init_container(
            '/var/cyberx/logs/horizon.log',
            '/var/cyberx/logs/horizon.stats.log',
            '/var/cyberx/horizon/plugins',
            '/var/cyberx/properties/horizon.properties'
        )
        super(self.__class__, self).extract_infrastructure_plugins_from_horizon_docker()


def main():
    components = [
        HorizonParserService('azure-iot-defender-horizon:release.1.0.20210221.1'),
        #TrafficMonitorService('azure-iot-defender-horizon:release.1.0.20210221.1'),
    ]

    for component in components:
        component.install()


if __name__ == '__main__':
    logger.debug('Executing {0}'.format(os.path.realpath(__file__)))
    try:
        main()
    except Exception as e:
        logger.error(e)
        sys.exit(1)
    finally:
        logger.debug('Exiting {0}'.format(os.path.realpath(__file__)))
