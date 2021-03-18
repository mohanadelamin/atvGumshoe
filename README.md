# atvGumshoe

atvGumshoe stand from Apple TV Gumshoe, it is a tool that can be used for Apple TV forensic:

The ATV Gumshoe has 8 options:

1. **Connect:** The connect option, *option 1*, is the first step while using the tool. The tool require ssh connection to the Jailbroken Apple TV device. Jailbroken Apple TV devices have SSH daemon enabled listing to port 44 with default user *root* and default password *alpine*. The connect step is required for all other options except the Exit. 
2. **Device Info:** After connecting to the Apple TV device, the analyst can request the device information using *option 2*, Device Info
3. **Keychain Trusted Peers:** *Option 3* extracts The Keychain Trusted Peers output from the Octagon Trust utility, which provides a view for the trust network used between the user Apple Devices.
4. **User Wifi information:** *Option 4* of the ATV Gumshoe tool print the list of Wifi networks that the Apple TV user connected to at one instance of time using any Apple Device with the same Apple ID account. The information is saved in Apple Cloud and synced with the Devices.
5. **User ID information:** Using *option 5* of the ATV Gumshoe tool it is possible to extract the user's Apple ID information and family member's IDs. Furthermore, it can also retrieve other nearby Users if available in the Apple Identity services cache synced with the Apple TV from other devices.
6. **User Location History:** Using *Option 6*, the ATV Gumshoe tool can also extract the user location history from Apple Cloud synced information; data can be from any user's devices. The details include the Name and Full Address of the place, the time stamp, and the application used as the source of the location details. In the example output below (LINK TO APPENDIX?), the location data were sourced from the user's iPhone device Mobile calendar.
7. **Installed Applications:** *Option 7* of the ATV Gumshoe help extract all the Apple TV installed application, both Apple internal Apps like Siri and Music, and Applications installed by the user from the Apple Store.
8. **Exit:** The last option, *option 0*, is used to Exit the program.


## Usage:

1. Clone the GitHub repo:
```
$ git clone https://github.com/mohanadelamin/atvGumshoe.git
```

2. Install Requirements:
```
$ cd atvGumshoe/
$ pip3 install -r requirements.txt
```

3. Run the tool:
```
$ python3 atvGumshoe.py
```

## atvGumshoe interface

```
    _  _______     __   ____ _   _ __  __ ____  _   _  ___  _____
   / \|_   _\ \   / /  / ___| | | |  \/  / ___|| | | |/ _ \| ____|
  / _ \ | |  \ \ / /  | |  _| | | | |\/| \___ \| |_| | | | |  _|
 / ___ \| |   \ V /   | |_| | |_| | |  | |___) |  _  | |_| | |___
/_/   \_\_|    \_/     \____|\___/|_|  |_|____/|_| |_|\___/|_____|


ATV Gumshoe is an Apple TV Logical Forensic Tool. (For Jailbroken Devices)

Please select an option
	1 : Connect
	2 : Device Info
        3 : Keychain Trusted Peers
        4 : User Wifi information
        5 : User ID information
        6 : User Location History
        7 : Installed Applications
        0 : Exit

Enter your choice : 0
```

## Disclaimer
The code in the repo are released under an as-is, best effort policy.