#!/usr/bin/env python3
#
#   Apple TV Gumshoe is a Digital Forensic Tool for Apple TV.
#
#   Requirements:
#       python >= 3.5
#
#       third-party library:
#           paramiko >= 2.7
#           scp >= 0.13
#
#        You should be able to install the third-party libraries via pip (or pip3
#        depending on the setup):
#
#           pip3 install paramiko scp
#

import os
import os.path
import json
import datetime
import sys
import pathlib
import stat
from argparse import ArgumentParser
from datetime import datetime as dt
from logging import basicConfig as logging_basicConfig, \
    addLevelName as logging_addLevelName, \
    getLogger as logging_getLogger, \
    log as logging_log, \
    DEBUG   as logging_level_DEBUG, \
    INFO    as logging_level_INFO, \
    WARN    as logging_level_WARN, \
    ERROR   as logging_level_ERROR, \
    debug   as debug, \
    info    as info, \
    warn    as warn, \
    error   as error
from paramiko.client import SSHClient as SSH_Client
from paramiko.ssh_exception import \
    BadHostKeyException as SSH_BadHostKeyException, \
    AuthenticationException as SSH_AuthenticationException, \
    SSHException as SSH_SSHException
from scp import SCPClient as SCP_Client
from clint.textui import colored
from colorama import Fore, Back, Style
from pyfiglet import Figlet
from getpass import getpass
from tabulate import tabulate

STATUS = False

FORENSIC_FILES = {
    'wifi': '/private/var/mobile/Library/SyncedPreferences/com.apple.wifid.plist',
}

LOGGING_LEVELS = {
    'ERROR': {
        'level': logging_level_ERROR,
        'name': 'ERROR',
        'xterm': '31m',
        '256color': '38;5;196m',
    },
    'NORMAL': {
        'level': 35,
        'name': 'CAD',
        'xterm': '37m',
        '256color': '38;5;255m',
    },
    'WARNING': {
        'level': logging_level_WARN,
        'name': 'WARNING',
        'xterm': '33m',
        '256color': '38;5;227m',
    },
    'INFO': {
        'level': logging_level_INFO,
        'name': 'INFO',
        'xterm': '36m',
        '256color': '38;5;45m',
    },
    'DEBUG': {
        'level': logging_level_DEBUG,
        'name': 'DEBUG',
        'xterm': '35m',
        '256color': '38;5;135m',
    },
}

#
# We allow the log level to be specified on the command-line or in the
# config by name (string/keyword), but we need to convert these to the
# numeric value:
#
LOGGING_LEVELS_MAP = {
    'NORMAL': LOGGING_LEVELS['NORMAL']['level'],
    'ERROR': logging_level_ERROR,
    'WARN': logging_level_WARN,
    'INFO': logging_level_INFO,
    'DEBUG': logging_level_DEBUG,
    'normal': LOGGING_LEVELS['NORMAL']['level'],
    'error': logging_level_ERROR,
    'warn': logging_level_WARN,
    'info': logging_level_INFO,
    'debug': logging_level_DEBUG
}


def logg(msg):
    """Wrapper function for calling logging.log with our 'NORMAL' level"""
    logging_log(LOGGING_LEVELS['NORMAL']['level'], msg)


def welcome(text):
    result = Figlet()
    return colored.cyan(result.renderText(text))


def ssh_login():
    global STATUS
    os.system("clear")
    print(welcome("ATV GUMSHOE"))
    host = input("Enter the Apple TV IP Address [192.168.1.151]: ") or "192.168.1.151"
    port = int(input("Enter the Apple TV SSH Port [44]: ") or 44)
    username = input("Enter the Apple TV username [root]: ") or "root"
    password = getpass("Enter the Apple TV password [alpine]: ") or "alpine"

    r = SSH_Client()
    r.load_system_host_keys()
    logg("Trying to open SSH connection to {}".format(host))
    try:
        r.connect(host, port=port, username=username, password=password)
    except Exception as err:
        logg("SSH connection to {} failed.".format(host))
        if input("Press any key to go to main menu."):
            return None

    logg("SSh connection to {} opened successfully. ".format(host))
    STATUS = True

    input("Press any key to go to main menu.")
    return r


def run_cmd(ssh_client, cmd):
    info("Trying to run the command: {}".format(cmd))
    try:
        (stdin, stdout, stderr) = ssh_client.exec_command(cmd)
        return stdout, stderr
    except:
        error("Running the command {} failed.".format(cmd))


def get_cfAbsoluteTime(seconds):
    utc_time = "Not Available"
    if seconds:
        cfAbsoluteTime = datetime.datetime.strptime("01-01-2001", "%m-%d-%Y")
        utc_time = cfAbsoluteTime + datetime.timedelta(seconds=seconds)
    return utc_time.strftime('%b %d %Y %H:%M:%S (Estimate)')



def main():
    global STATUS
    ssh_client = ''
    plutil_json = 'plutil -showjson '
    while True:
        os.system("clear")
        print(welcome("ATV GUMSHOE"))
        print("Please select an option ")
        if STATUS:
            tv_tuple = ssh_client.get_transport().getpeername()
            print("\t1 : Connect (Already Connected to {}:{})".format(tv_tuple[0], tv_tuple[1]))
        else:
            print("\t1 : Connect")
        print("""\t2 : Device Info
        3 : Keychain Trusted Peers
        4 : User Wifi information
        0 : Exit""")
        c = input("\nEnter your choice : ")

        if c == '1':
            ssh_client = ssh_login()
        elif c == '2':
            if STATUS:
                pass
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '3':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            if STATUS:
                cmd = 'otctl status -j'
                result_out, result_err = run_cmd(ssh_client, cmd)
                result_data = json.load(result_out)
                trusted_peers = result_data['contextDump']['self']['dynamicInfo']['included']
                excluded_peers = result_data['contextDump']['self']['dynamicInfo']['excluded']
                trusted_peers_list = []
                excluded_peers_list = []
                self_list = []
                for peer in result_data['contextDump']['peers']:
                    if peer['peerID'] in trusted_peers:
                        trusted_peers_list.append([peer['peerID'],
                                                   peer['stableInfo']['serial_number'],
                                                   peer['permanentInfo']['model_id'],
                                                   peer['stableInfo']['os_version']])
                    elif peer['peerID'] in excluded_peers:
                        excluded_peers_list.append([peer['peerID'],
                                                    peer['stableInfo']['serial_number'],
                                                    peer['permanentInfo']['model_id'],
                                                    peer['stableInfo']['os_version']])
                self_list.append([result_data['contextDump']['self']['peerID'],
                                  result_data['contextDump']['self']['stableInfo']['serial_number'],
                                  result_data['contextDump']['self']['permanentInfo']['model_id'],
                                  result_data['contextDump']['self']['stableInfo']['os_version']])
                print("\nDevice Trust Network collected from the Octagon Trust utility - otctl:\n")
                print("Device Self Information:")
                print(tabulate(self_list, headers=['ID', 'SN', 'Model', 'OS Version']))
                print("\nTrusted peers:")
                print(tabulate(trusted_peers_list, headers=['Peer ID', 'SN', 'Model', 'OS Version']))
                print("\nExcluded peers:")
                print(tabulate(excluded_peers_list, headers=['Peer ID', 'SN', 'Model', 'OS Version']))
                input("\nPress any key to go to main menu.")
                continue
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '4':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            if STATUS:
                wifi_dict = {}
                cmd = plutil_json + FORENSIC_FILES['wifi']
                result_out, result_err = run_cmd(ssh_client, cmd)
                result_out_utf8 = result_out.read().decode("utf-8").replace(":,",":\"\",")
                result_data = json.loads(result_out_utf8)
                for ssid in result_data['values']:
                    wifi_dict[ssid] = [
                        result_data['values'][ssid]['value'].get('added_by', "Not Available"),
                        result_data['values'][ssid]['value'].get('added_by_os_ver', "Not Available"),
                        result_data['values'][ssid]['value'].get('added_at',
                                                                 get_cfAbsoluteTime(
                                                                     result_data['values'][ssid].get("timestamp", None))
                                                                 )
                    ]

                headers = ["SSID", "ADDED BY", "OS VERSION", "ADDED AT (UTC)"]
                print(tabulate([[k,] + v for k,v in sorted(wifi_dict.items(), key=lambda i:i[1][2]) ],headers = headers))
                input("\nPress any key to go to main menu.")
                continue
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '0':
            if STATUS:
                info("Closing SSH Connection")
                ssh_client.close()
            info("Bye!")
            exit()
        os.system("clear")


if __name__ == "__main__":
    main()
