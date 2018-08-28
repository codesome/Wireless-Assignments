#!/bin/bash


if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <interface> <SSID> <password> <channel>"
    echo "Example: $0 wlp2s0 MyHotspot AwesomePwd 6"
    exit 1
fi

INTERFACE=$1
SSID=$2
PASSWORD=$3
CHANNEL=$4

echo "Starting hotspot with SSID=$SSID on Channel $CHANNEL"

nmcli dev wifi hotspot ifname $INTERFACE ssid $SSID band bg channel $CHANNEL password $PASSWORD