#!/usr/bin/python3

from setuptools import setup, find_packages
import glob

VERSION = "0.8.2"

data_files = [
        ('/usr/share/qomui', ['resources/countries.json']),
        ('/usr/share/applications/', ['resources/qomui.desktop']),
        ('/usr/lib/systemd/system/', ['systemd/qomui.service']),
        ('/usr/share/dbus-1/system.d/', ['systemd/org.qomui.service.conf']),
        ('/usr/share/dbus-1/system-services/', ['systemd/org.qomui.service']),
        ('/usr/share/icons/hicolor/scalable/apps/', ['resources/qomui.svg',
                                                     'resources/qomui_off.svg']),
        ('/usr/share/qomui/', [
                                'resources/AzireVPN_config',
                                'resources/Airvpn_config',
                                'resources/PIA_config',
                                'resources/ProtonVPN_config',
                                'resources/Windscribe_config',
                                'resources/Airvpn_config_old',
                                'resources/Mullvad_config',
                                'resources/Mullvad_config_old',
                                'resources/PIA_config_old',
                                'resources/ProtonVPN_config_old',
                                'resources/Windscribe_config_old',
                                'resources/default_config.json',
                                'resources/firewall_default.json',
                                'resources/ssl_config',
                                'resources/qomui.png',
                                'resources/airvpn_api.pem',
                                'resources/airvpn_cacert.pem',
                                'VERSION']
                            ),
        ('/usr/share/qomui/scripts/', [
                                        'scripts/hop.sh',
                                        'scripts/hop_down.sh',
                                        'scripts/bypass_up.sh',
                                        'scripts/bypass_route.sh'
                                       ]),
        ('/usr/share/qomui/flags/', glob.glob('resources/flags/*'))
        ]


setup(name="qomui",
      version=VERSION,
      packages=['qomui'],
      include_package_data=True,
      install_requires=[
        'beautifulsoup4',
        'pexpect',
        'psutil',
        'requests',
        'lxml'
        ],
      classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Topic :: Internet',
        'Topic :: Security',
        ],
      data_files = data_files,
      license='GPLv3+',
      entry_points={
        'gui_scripts': [
            'qomui-gui=qomui.qomui_gui:main'
            ],
        'console_scripts': [
            'qomui-service=qomui.qomui_service:main',
            'qomui-cli=qomui.qomui_cli:main'
            ]},
      )
