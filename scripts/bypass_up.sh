#!/bin/bash

/sbin/ip route del default table bypass_qomui
/sbin/ip route add default via $route_vpn_gateway dev $dev metric 1 table bypass_qomui
exit 0
