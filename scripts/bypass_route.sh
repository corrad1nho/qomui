#!/bin/bash

if [ "$1" == "route" ] ; then
    echo "Setting route for table bypass_qomui" $@
    /sbin/ip $@ table bypass_qomui
else
    /sbin/ip $@
fi
