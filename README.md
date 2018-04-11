## Qomui
--------------------
Written in Python 3.6

### Description
Qomui(Qt OpenVPN Management UI) is a easy-to-use OpenVPN Gui for GNU/Linux with some unique features such as provider-independent support for double-hop connections. Qomui supports multiple providers with added convenience when using AirVPN or Mullvad. 

### Features
-should work with all VPN providers that offer OpenVPN config files 
-automatic download function for Mullvad and AirVPN 
-support for OpenVPN over SSL and SSH for AirVPN
-allows double-hop VPN connections (VPN chains) between different providers (currently tested with AirVPN, Mullvad and ProtonVPN). 
-Gui written in PyQt including option to minimze application to system tray
-security-conscious separation of the gui and a D-Bus service that handles commands that require root privileges
-protection against DNS leaks
-iptables-based, configurable firewall that blocks all outgoing network traffic in case the VPN connection breaks down 


### Dependencies/Requirements
- Qomui should work on any GNU/Linux distribution.
- python(>=3.5)
- setuptools and (optionally) pip
- python-pyqt5, python-dbus, and python dbus.mainloop.pyqt5 
- openvpn, dnsutils, and stunnel
- geoip and geoip-database (optional: to identify server locations)

Additionally, the following python modules are required:
- psutil
- requests
- pycountry
- beautifulsoup4
- lxml
- pexpect

In case the latter are not present on your system these will be automatically installed when running setup.py. I would recommend installing the following python packages with your distribution's package manager, though.

### Installation
To install all dependencies in one go on Arch-based distributions run the following command:

'''
sudo pacman -S python python-setuptools python-pip python-pyqt5 python-dbus openvpn stunnel dnsutils geoip geoip-database python-psutil python-requests python-lxml python-beautifulsoup4 python-pycountry python-pexpect
'''


The equivalent for Debian-based distributions is:

'''
sudo apt install python3 python3-setuptools python3-pip python3-pyqt5 python3-dbus python3-dbus.mainloop.pyqt5 openvpn stunnel dnsutils geoip-bin geoip-database python3-psutil python3-requests python3-lxml python3-bs4 python3-pycountry python3-pexpect
'''


To install Qomui, simply issue the following commands:

'''
git clone https://github.com/corrad1nho/qomui.git
cd ./
'''

Arch:

'''
sudo pip install ./
'''

Debian:

'''
sudo pip3 install ./
'''

Alternatively:

'''
sudo python setup.py install
'''

### General usage:
Qomui contains two components: qomui-gui and qomui-service. The latter exposes methods via D-Bus and can be controlled via systemd (alternatively you can start it with "sudo qomui-service"). Be aware that if you choose to activate the firewall and enable qomui-service all internet connectivity will be blocked as long as no OpenVPN connection has been established whether or not the gui is running. 

Current configurations for AirVPN and Mullvad can be automatically downloaded via the update button in the respective tab. For all other providers you can conveniently add multiple config files at once in the third tab. Qomui will automatically resolve host names, determine the location of servers (using geoip-database) and save your username and password (in a file readable only by root). Modified config files will be saved as "QOMUI-NameOfConfigFile" in the same directory as the original files. 

### Double-Hop:
To create a "double-hop" simply choose a first server via the "hop"-button before connecting to the second one. You can mix connections to different providers. However, the double-hop feature does not support OpenVPN over SSL or SSH. Also be aware that depending on your choice of servers this feature may drastically reduce the speed of your internet connection and increase your ping. In any case, you will likely have to sacrifice some bandwith. In my opinion, the added benefits of increased privacy, being able to use different providers as entry and exit node and making it more difficult to be tracked are worth it, though. This feature was inspired by suggestions to simply run a second instance of OpenVPN in a virtual machine to create a double-hop. If that is possible, it should be possible to do the same by manipulating the routing table without the need to fire up a VM. Invaluable resources on the topic were [this discussion on the Openvpn forum](https://forums.openvpn.net/viewtopic.php?f=15&t=7483) and [this github repository](https://github.com/TomAshley303/VPN-Chain). 

### About this project
Qomui has been my first ever programming experience and a practical challenge for myself to learn a bit of Python. Hence, I'm aware that there is a lot of code that could probably be improved, streamlined and made more beautiful. I might have made some horrible mistakes, too. I'd appreciate any feedback as well as suggestions for new features.





