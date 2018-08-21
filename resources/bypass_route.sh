#!/bin/bash

if [ "$1" == "route" ] ; then
    echo "Setting route for table bypass_qomui" $@
    ip $@ table bypass_qomui
else
    ip $@
fi
