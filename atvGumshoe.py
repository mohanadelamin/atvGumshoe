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
import re
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
    'id_cache': '/private/var/mobile/Library/Preferences/com.apple.identityservices.idstatuscache.plist',
    'location': '/private/var/mobile/Library/SyncedPreferences/com.apple.cloudrecents.CloudRecentsAgent-com.apple.eventkit.locations.plist',
    'app_ids' : '/private/var/mobile/Library/UserNotificationsServer/Library.plist',
    'apple_app_info': '/Applications/APPNAME/Info.plist',
    'other_app_info': '/private/var/containers/Bundle/Application/UUID/iTunesMetadata.plist',
    'appstored': '/private/var/mobile/Library/Preferences/com.apple.appstored.plist',
    'tvsettings': '/private/var/mobile/Library/Preferences/com.apple.TVSettings.plist',
    'systemversion': '/System/Library/CoreServices/SystemVersion.plist'
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
    return utc_time.strftime('%b %d %Y %H:%M:%S  (Estimate)')


def fix_json(json_data):
    replacements = {
        (',{1,}]', ']'),
        (':}', ':\"\"}'),
        (':,', ':\"\",')
    }

    for o,n in replacements:
        json_data = re.sub(o, n, json_data)

    return json_data

def main():
    global STATUS
    ssh_client = ''
    plutil_json = 'plutil -showjson '
    ls = 'ls '
    while True:
        os.system("clear")
        print(welcome("ATV GUMSHOE"))
        print("ATV Gumshoe is an Apple TV Logical Forensic Tool. (For Jailbroken Devices)\n")
        print("Please select an option ")
        if STATUS:
            tv_tuple = ssh_client.get_transport().getpeername()
            print("\t1 : Connect (Already Connected to {}:{})".format(tv_tuple[0], tv_tuple[1]))
        else:
            print("\t1 : Connect")
        print("""\t2 : Device Info
        3 : Keychain Trusted Peers
        4 : User Wifi information
        5 : User ID information
        6 : User Location History
        7 : Installed Applications
        0 : Exit""")
        c = input("\nEnter your choice : ")

        if c == '1':
            try:
                ssh_client = ssh_login()
            except Exception as err:
                print("SSH Connection failed - {}".format(err))
        elif c == '2':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            print("*** Device Information ***\n")
            if STATUS:
                try:
                    serial_number = ''
                    os_version = ''
                    os_build = ''
                    hw_model = ''
                    device_id = ''

                    # Get device Serial Number
                    try:
                        cmd = 'otctl status -j'
                        result_out, result_err = run_cmd(ssh_client, cmd)
                        result_data = json.load(result_out)
                        serial_number = result_data['contextDump']['self']['stableInfo']['serial_number']
                    except Exception as err:
                        print("Getting Device Serial Number Failed - {}".format(err))

                    # Get OS Version
                    try:
                        cmd = plutil_json + FORENSIC_FILES['systemversion']
                        result_out, result_err = run_cmd(ssh_client, cmd)
                        result_out_utf8 = fix_json(result_out.read().decode("utf-8"))
                        result_data = json.loads(result_out_utf8)
                        os_version = result_data['ProductName'] + ' ' \
                                     + result_data['ProductVersion']
                        os_build = result_data['ProductBuildVersion']
                    except Exception as err:
                        print("Getting OS Version Failed - {}".format(err))

                    # Get HW Model
                    try:
                        cmd = plutil_json + FORENSIC_FILES['tvsettings']
                        result_out, result_err = run_cmd(ssh_client, cmd)
                        result_out_utf8 = fix_json(result_out.read().decode("utf-8"))
                        result_data = json.loads(result_out_utf8)
                        hw_model = result_data['SSDeviceType']['hardwareModel']
                    except Exception as err:
                        print("Getting HW Model Failed - {}".format(err))

                    # Get Device ID
                    try:
                        cmd = plutil_json + FORENSIC_FILES['appstored']
                        result_out, result_err = run_cmd(ssh_client, cmd)
                        result_out_utf8 = fix_json(result_out.read().decode("utf-8"))
                        result_data = json.loads(result_out_utf8)
                        device_id = result_data['ArcadeDeviceGUID']
                    except Exception as err:
                        print("Getting Device ID Failed - {}".format(err))

                    print('Serial Number: {}'.format(serial_number))
                    print('HW Model: {}'.format(hw_model))
                    print('OS Version: {}'.format(os_version))
                    print('OS Built: {}'.format(os_build))
                    print('Device ID: {}'.format(device_id))

                except Exception as err:
                    print("Getting Device Info Failed - {}".format(err))
                input("\nPress any key to go to main menu.")
                continue
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '3':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            print("*** Keychain Trusted Peers ***\n")
            print("Data source: Octagon Trust utility - otctl\n")
            if STATUS:
                try:
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
                except Exception as err:
                    print("Getting Keychain Trusted Peers Failed - {}".format(err))
                input("\nPress any key to go to main menu.")
                continue
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '4':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            print("*** User Wifi information ***\n")
            print("Data source file: " + FORENSIC_FILES['wifi'] + '\n')
            if STATUS:
                try:
                    wifi_dict = {}
                    cmd = plutil_json + FORENSIC_FILES['wifi']
                    result_out, result_err = run_cmd(ssh_client, cmd)
                    #result_out_utf8 = result_out.read().decode("utf-8").replace(":,",":\"\",")
                    result_out_utf8 = fix_json(result_out.read().decode("utf-8"))
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
                    #print(tabulate([[k,] + v for k,v in sorted(wifi_dict.items(), key=lambda i:i[1][2]) ],headers = headers))
                    print(
                        tabulate([[k, ] + v for k, v in wifi_dict.items()], headers=headers))
                except Exception as err:
                    print("Getting User Wifi information Failed - {}".format(err))
                input("\nPress any key to go to main menu.")
                continue
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '5':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            print("*** User ID information ***\n")
            print("Data source file: " + FORENSIC_FILES['id_cache'] + '\n')
            if STATUS:
                try:
                    id_dict = {
                        'icloud': [],
                        'fmd': [],
                        'cloudmessaging': [],
                        'nearby': [],
                    }
                    cmd = plutil_json + FORENSIC_FILES['id_cache']
                    result_out, result_err = run_cmd(ssh_client, cmd)
                    #result_out_utf8 = result_out.read().decode("utf-8").replace(":,", ":\"\",")
                    result_out_utf8 = fix_json(result_out.read().decode("utf-8"))
                    result_data = json.loads(result_out_utf8)
                    for record in result_data.keys():
                        if 'icloudpairing' in record:
                            id_dict['icloud'] = result_data[record].keys()
                        elif 'fmd' in record:
                            id_dict['fmd'] = result_data[record].keys()
                        elif 'cloudmessaging' in record:
                            id_dict['cloudmessaging'] = result_data[record].keys()
                        elif 'nearby' in record:
                            id_dict['nearby'] = result_data[record].keys()
                    headers = ['Number','ID']
                    print("User Apple ID:")
                    print(tabulate(zip(range(1,len(id_dict['icloud'])+1),id_dict['icloud']),headers=headers))
                    print("\nUser family member IDS:")
                    print(tabulate(zip(range(1,len(id_dict['fmd'])+1),id_dict['fmd']),headers=headers))
                    print("\nUser messaging IDs:")
                    print(tabulate(zip(range(1,len(id_dict['cloudmessaging'])+1),id_dict['cloudmessaging']),headers=headers))
                    print("\nUser nearby IDs:")
                    print(tabulate(zip(range(1,len(id_dict['nearby'])+1),id_dict['nearby']),headers=headers))
                except Exception as err:
                    print("Getting User ID information Failed - {}".format(err))
                input("\nPress any key to go to main menu.")
                continue
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '6':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            print("*** User Location History ***\n")
            print("Data source file: " + FORENSIC_FILES['location'] + '\n')
            if STATUS:
                try:
                    location_list = []
                    cmd = plutil_json + FORENSIC_FILES['location']
                    result_out, result_err = run_cmd(ssh_client, cmd)
                    result_out_utf8 = fix_json(result_out.read().decode("utf-8"))
                    result_data = json.loads(result_out_utf8)

                    for record in result_data['values'].keys():
                        location_list.append([
                            result_data['values'][record]['value'].get('n', "Not Available"),
                            result_data['values'][record]['value'].get('a', "Not Available"),
                            get_cfAbsoluteTime(result_data['values'][record].get("timestamp", None)),
                            result_data['values'][record]['value'].get('S', "Not Available"),
                        ])
                    headers = ['Name','Address','Timestamp (UTC)','Source']
                    print(tabulate(location_list, headers=headers))
                except Exception as err:
                    print("Getting User Location History Failed - {}".format(err))
                input("\nPress any key to go to main menu.")
                continue
            else:
                error("No device connected.")
                input("Press any key to go to main menu.")
                continue
        elif c == '7':
            os.system("clear")
            print(welcome("ATV GUMSHOE"))
            print("*** Installed Application ***\n")
            if STATUS:
                try:
                    apple_app_list = []
                    other_app_list = []

                    # Get the list of Apple Installed Apps
                    cmd = ls + FORENSIC_FILES['apple_app_info'].split("/APPNAME/")[0]
                    apple_result_out, apple_result_err = run_cmd(ssh_client, cmd)


                    # Parse the Apple Apps information
                    for app in apple_result_out.readlines():
                        cmd = plutil_json + FORENSIC_FILES['apple_app_info'].replace('APPNAME', app.rstrip())
                        apple_result_out, result_err = run_cmd(ssh_client, cmd)
                        apple_result_out_utf8 = fix_json(apple_result_out.read().decode("utf-8"))
                        apple_result_data = json.loads(apple_result_out_utf8)
                        apple_app_list.append([apple_result_data["CFBundleName"],
                                               apple_result_data["CFBundleVersion"],
                                               apple_result_data["CFBundleIdentifier"]])

                    # Print Application Lists
                    print("** Apple Internal Applications **")
                    print("Data location /Applications/<APPNAME>/Info.plist\n")
                    headers = ['App Name','App Version','App Bundle ID']
                    print(tabulate(apple_app_list, headers=headers))

                    # Get the list of Other Installed Apps
                    cmd = ls + FORENSIC_FILES['other_app_info'].split("/UUID/")[0]
                    other_result_out, other_result_err = run_cmd(ssh_client, cmd)
                    # Parse the Other Apps information
                    for app in other_result_out.readlines():
                        cmd = plutil_json + FORENSIC_FILES['other_app_info'].replace('UUID', app.rstrip())
                        other_result_out, other_result_err = run_cmd(ssh_client, cmd)
                        other_result_out_utf8 = fix_json(other_result_out.read().decode("utf-8"))
                        other_result_data = json.loads(other_result_out_utf8)
                        other_app_list.append([other_result_data["itemName"],
                                               other_result_data["bundleVersion"],
                                               other_result_data["softwareVersionBundleId"]])

                    print("\n\n** User Installed Applications **")
                    print("Data location /private/var/containers/Bundle/Application/<APP UUID>/iTunesMetadata.plist\n")
                    print(tabulate(other_app_list, headers=headers))

                except Exception as err:
                    print("Getting User Location History Failed - {}".format(err))
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
