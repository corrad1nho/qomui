## Qomui
--------------------
Written in Python 3.6

### Description
Qomui (Qt OpenVPN Management UI) is an easy-to-use OpenVPN Gui for GNU/Linux with some unique features such as provider-independent support for double-hop connections. Qomui supports multiple providers with added convenience when using AirVPN, PIA or Mullvad. 

### Features
- should work with all VPN providers that offer OpenVPN config files 
- automatic download function for Mullvad, Private Internet Access and AirVPN 
- support for OpenVPN over SSL and SSH for AirVPN
- allows double-hop VPN connections (VPN chains) between different providers (currently tested with AirVPN, Mullvad and ProtonVPN). 
- Gui written in PyQt including option to minimize application to system tray 
- security-conscious separation of the gui and a D-Bus service that handles commands that require root privileges
- protection against DNS leaks/ipv6 leaks
- iptables-based, configurable firewall that blocks all outgoing network traffic in case the VPN connection breaks down
- allow applications to bypass the OpenVPN tunnel - to watch Netflix for example

### Dependencies/Requirements
- Qomui should work on any GNU/Linux distribution 
- python (>=3.5)
- python-pyqt5, python-dbus, and python-dbus.mainloop.pyqt5, python-setuptools, pip 
- Additional python packages: psutil, requests, pycountry, beautifulsoup4, lxml, pexpect
- openvpn, dnsutils and stunnel
- geoip and geoip-database (optional: to identify server locations)
- dnsmasq, libcgroup, libcgroup-tools, iptables >= 1.6 (optional: required for bypassing OpenVPN)

### Installation

#### Ubuntu

Download and install [DEB-Package](https://github.com/corrad1nho/qomui/releases/download/v0.5.1/qomui-0.5.1-amd64.deb)

#### Fedora

Download and install [RPM-Package](https://github.com/corrad1nho/qomui/releases/download/v0.5.1/qomui-0.5.1-1.x86_64.rpm)

#### Arch

Qomui is available on the AUR:

```
yaourt -S qomui
```

#### Source

Make sure all dependencies are installed - be aware that depending on your distribution package names may vary!

```
git clone https://github.com/corrad1nho/qomui.git
cd ./qomui
sudo python3 setup.py install
```


### Usage
Qomui contains two components: qomui-gui and qomui-service. The latter exposes methods via D-Bus and can be controlled via systemd (alternatively you can start it with "sudo qomui-service"). Be aware that if you choose to activate the firewall and enable qomui-service all internet connectivity will be blocked as long as no OpenVPN connection has been established whether or not the gui is running. 

Current configurations for AirVPN and Mullvad can be automatically downloaded via provider tab. For all other providers you can conveniently add a config file folder. Qomui will automatically resolve host names, determine the location of servers (using geoip-database) and save your username and password (in a file readable only by root). Modified config files will be saved as "QOMUI-NameOfConfigFile" in the same directory as the original files. 

### Double-Hop
To create a "double-hop" simply choose a first server via the "hop"-button before connecting to the second one. You can mix connections to different providers. However, the double-hop feature does not support OpenVPN over SSL or SSH. Also be aware that depending on your choice of servers this feature may drastically reduce the speed of your internet connection and increase your ping. In any case, you will likely have to sacrifice some bandwith. In my opinion, the added benefits of increased privacy, being able to use different providers as entry and exit node and making it more difficult to be tracked are worth it, though. This feature was inspired by suggestions to simply run a second instance of OpenVPN in a virtual machine to create a double-hop. If that is possible, it should be possible to do the same by manipulating the routing table without the need to fire up a VM. Invaluable resources on the topic were [this discussion on the Openvpn forum](https://forums.openvpn.net/viewtopic.php?f=15&t=7483) and [this github repository](https://github.com/TomAshley303/VPN-Chain). 

### Bypass OpenVPN
Qomui includes the option to allow applications such as web browsers to bypass an existing OpenVPN tunnel. This feature is fully compatible with Qomui's firewall activated and double-hop connections. When activated, you can either add and launch applications via the respective tab or via console by issuing your command the following way:

```
cgexec -g net_cls:bypass_qomui $yourcommand
```
The idea is taken from [this post on severfault.com](https://serverfault.com/questions/669430/how-to-bypass-openvpn-per-application/761780#761780). Essentially, running an application outside the OpenVPN tunnel works by putting it in a network control group. This allows classifying and identifying network packets from processes in this cgroup in order to route them differently. Be aware that the implementation of this feature is still experimental. 

### About this project
Qomui has been my first ever programming experience and a practical challenge for myself to learn a bit of Python. Hence, I'm aware that there is a lot of code that could probably be improved, streamlined and made more beautiful. I might have made some horrible mistakes, too. I'd appreciate any feedback as well as suggestions for new features.

### Changelog
version 0.5.1:
- [new] support for ipv6/tls-crypt configs from AirVPN - EXPERIMENTAL
- [bugfix] firewall dialog not opening on new installations
- [bugfix] random crashes when tunnel interface not available
- [bugfix] update offered even though latest version installed

version 0.5.0:
- [new] Reconnect when OpenVPN unexpectedly dies
- [new] Update Qomui via new "About" tab - EXPERIMENTAL
- [new] Option to use simplified tray icon to avoid glitches
- [new] Protocol/port of active connection displayed
- [new] Tray icon shows connection status 
- [new] Automatic reconnects when OpenVPN tunnel breaks
- [change] Disconnect button always visible
- [bugfix] Config file / firewall configuration overwritten after update
- [bugfix] Crashes due to missing entry in config file
- [bugfix] Crashes when modifying server during latency check
- [bugfix] Changing country in modify dialog fails
- [bugfix] Connection attempt fails when protocol/port not set
- [bugfix] Wireguard servers downloaded from Mullvad even though not supported


