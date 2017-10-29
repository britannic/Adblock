#!/usr/bin/env bash
#
# **** License ****
# COPYRIGHT AND LICENCE
#
# Copyright (C) 2017 Helmrock Consulting
#
# This library is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself, either Perl version 5.23.4 or,
# at your option, any later version of Perl 5 you may have available.
#
# Author: Neil Beadle
# Description: Scripts for creating dnsmasq configuration files to redirect dns
# look ups to alternative IPs (blackholes, pixel servers etc.)
# **** End License ****
#
# Author: Neil Beadle
# Description: This script cleans up orphaned configure sessions and releases
# disk space

VERSION='0.7'
ME=$(basename ${0})

# Comment/uncomment line below for debug
# DEBUG="echo Dry run, this command would be executed: "

# Make sure script runs as root
if [[ ${EUID} != 0 ]]
then
  echo "${ME} version ${VERSION} must be run as root, use: [sudo $(pwd)/${ME}]"
  exit 1
fi

if [[ $(ps -a | grep -e 'newgrp$') ]]
then
    echo "Configure session running - exit 'configure' before running this script!"
    exit 1
else
    for i in /opt/vyatta/config/tmp/new*
    do
        if [[ -d "${i}" ]]
        then
            echo "Unmounting ${i}..."
            ${DEBUG} umount "${i}"
            if [[ ${?} == 0 ]]
            then
                echo "${i} unmounted."
            else
                echo "Error: Couldn't unmount ${i}!"
            fi
            if [[ -d "${i}" ]]
            then
                echo "Removing directory ${i}..."
                ${DEBUG} rm -rf "${i}"
            fi
        fi
    done
    for i in /opt/vyatta/config/tmp/*
    do
        if [[ -d "${i}" ]]
        then
            echo "Removing directory ${i}..."
            ${DEBUG} rm -rf "${i}"
        fi
    done
    for i in /tmp/changes_only_*
    do
        if [[ -d "${i}" ]]
        then
            echo "Removing directory ${i}..."
            ${DEBUG} rm -rf "${i}"
        fi
    done
    for i in /tmp/config.new.boot.*
    do
        if [[ ! -s "${i}" ]]
        then
            echo "Removing file ${i}..."
            ${DEBUG} rm -rf "${i}"
        fi
    done
fi
