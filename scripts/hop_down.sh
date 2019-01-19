#!/bin/bash

/sbin/route del -net $1 netmask 255.255.255.255 gw _gateway


#OLD VERSION
# while getopts “:f:s” HOP
# do
#      case $HOP in
#          f)  echo "/sbin/route del -net $2 netmask 255.255.255.255 gw _gateway"
#             /sbin/route del -net $2 netmask 255.255.255.255 gw _gateway
#             #/sbin/route del -net $3 netmask 255.255.255.255 gw $ifconfig_local
#              ;;
#             
#          s) 
#             /sbin/route del -net 0.0.0.0 netmask 128.0.0.0 gw $ifconfig_local
#             /sbin/route del -net 128.0.0.0 netmask 128.0.0.0 gw $ifconfig_local
#              ;;
#      esac
# done

