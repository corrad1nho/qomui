##Changelog

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

version 0.4.1:
- [bugfix] Crashes if no port/protocol selected
- [bugfix] Crashes while performing latency checks if not connected to a network
- [bugfix] Tray icon not displayed on Linux Mint Cinnamon 18.3
- [bugfix] Cannot toggle "autoconnect" option
- [bugfix] Crashes if checking latencies while new servers are added

version 0.4:
- [new] Check and sort servers by latency
- [new] Additional info for active connection displayed 
- [bugfix] Disable ipv6 option status not displayed correctly
- [bugfix] List of applications is empty if not all default application directories exist
- [bugfix] Minimizing/maximizing window does not work on Mint Cinnamon 18.3

version 0.3.1
- [new] Modify imported servers and config files
- [change] Improved performance of server list
- [change] Mullvad: Updated link to parse server info
- [bugfix] Crashes when deleting server/provider fixed
- [bugfix] Memory leak in server tab fixed

version 0.3
- [new] Mark servers as favourites
- [new] Randomly connect to a favourite server
- [new] Support for PIA (PrivateInternetAccess)
- [new] Override Port/Protocol in imported configs
- [change] Config file import improved
- [change] All servers displayed in one tab
- [bugfix] Crashes after hibernate

version 0.2
- [new] OpenVPN bypass
- [change] DNS management
