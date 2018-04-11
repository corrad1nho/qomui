#!/bin/bash

pre_gateway=$(ip route | awk 'FNR==1 {print $3}')

while getopts “:f:s” HOP
do
     case $HOP in
         f)  
            /sbin/route add -net $2 netmask 255.255.255.255 gw $pre_gateway 
            /sbin/route add -net $3 netmask 255.255.255.255 gw $ifconfig_local
             ;;
            
         s) 
            /sbin/route add -net 0.0.0.0 netmask 128.0.0.0 gw $ifconfig_local
            /sbin/route add -net 128.0.0.0 netmask 128.0.0.0 gw $ifconfig_local
             ;;
     esac
done

