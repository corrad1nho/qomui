# Qomui <img align="right" src="resources/qomui.png" width=40> 

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
- allow applications to bypass the VPN tunnel - to watch Netflix for example
- experimental support for Wireguard
- command-line interface

### Dependencies/Requirements
- Qomui should work on any GNU/Linux distribution 
- python (>=3.5)
- python-pyqt5, python-dbus, and python-dbus.mainloop.pyqt5, python-setuptools, pip 
- Additional python packages: psutil, requests, pycountry, beautifulsoup4, lxml, pexpect
- openvpn, dnsutils and stunnel
- geoip and geoip-database (optional: to identify server locations)
- dnsmasq, libcgroup, libcgroup-tools, iptables >= 1.6 (optional: required for bypassing OpenVPN)
- wireguard-tools, openresolv (optional: wireguard)

### Installation

#### Ubuntu

Download and install [DEB-Package](https://github.com/corrad1nho/qomui/releases/download/v0.6.0/qomui-0.6.0-amd64.deb)

#### Fedora

Download and install [RPM-Package](https://github.com/corrad1nho/qomui/releases/download/v0.6.0/qomui-0.6.0-1.x86_64.rpm)

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

### Wireguard
You can add wireguard config files from any provider as easily as OpenVPN files. Wireguard configs for Mullvad are now downloaded automatically alongside their OpenVPN configs as long as Wireguard is installed. As of now, Wireguard will not be installed automatically with DEB and RPM packages. You can find the official installation guidelines for different distributions [here](https://www.wireguard.com/install/).

### Cli
The cli interface is still experimental and missing some features, e.g. automatic reconnects. Avoid using the cli and the Gui concurrently. 

#### Example usage

Add config files:
```
qomui-cli -a $provider
```
Connect to a server:
```
qomui-cli -c $server
```
Activate options (e.g. firewall):
```
qomui-cli -e firewall
```
List and filter available servers:
```
qomui-cli -l Airvpn "United States"
```
To see all other available options:
```
qomui-cli --help
```

### About this project
Qomui has been my first ever programming experience and a practical challenge for myself to learn a bit of Python. Hence, I'm aware that there is a lot of code that could probably be improved, streamlined and made more beautiful. I might have made some horrible mistakes, too. I'd appreciate any feedback as well as suggestions for new features.

### Changelog
version 0.6.0:
- [new] support for Wireguard
- [new] cli-interface
- [change] additional parameters parsed from .desktop-files
- [change] update routine now uses dpkg/rpm if installed as DEB/RPM package - reinstall required!
- [bugfix] crashes at start when system tray not available
- [bugfix] Info for active connection sometimes not updated correctly 
- [bugfix] Doublehop fails on Fedora 

version 0.5.1:
- [new] support for ipv6/tls-crypt configs from AirVPN - EXPERIMENTAL
- [bugfix] firewall dialog not opening on new installations
- [bugfix] random crashes when tunnel interface not available
- [bugfix] update offered even though latest version installed


