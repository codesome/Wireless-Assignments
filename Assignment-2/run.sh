# !/bin/bash

echo "# Getting channel utilization"
sudo iwlist wlp2s0 scan | grep Frequency | sort | uniq -c | sort -n > utilization_list.txt

echo 
echo "# Calculation best channel to start hotspot"
python channelUtilization.py utilization_list.txt

CHANNEL=$?

echo 
echo "# Starting hotspot"
./hotspot.sh wlp2s0 CS15BTECH11018 password $CHANNEL