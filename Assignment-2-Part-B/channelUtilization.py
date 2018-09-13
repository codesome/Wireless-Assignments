import sys
import os

channelFreq = {
    1: "2412",
    2: "2417",
    3: "2422",
    4: "2427",
    5: "2432",
    6: "2437",
    7: "2442",
    8: "2447",
    9: "2452",
    10: "2457",
    11: "2462",
    12: "2467",
    13: "2472",
    14: "2484",
}

def channelToFreq(channel):
    return "("+str(channelFreq[channel])+"MHz)"

with open(sys.argv[1]) as f:
    lines = f.readlines()

lines = [x.strip() for x in lines]

leastLoadedChannel = 0
leastLoad = 10000000000

leastLoadedOrthogonalChannel = 1
leastOrthogonalLoad = 10000000000

for line in lines:
    components = line.split("Frequency:")
    load = components[0]
    components = components[1].split("(Channel ")
    channel = components[1].split(")")[0]
    load = int(load)
    channel = int(channel)

    if load < leastLoad:
        leastLoad = load 
        leastLoadedChannel = channel
    if (channel==1 or channel==6 or channel==11) and load < leastOrthogonalLoad:
        leastOrthogonalLoad = load
        leastLoadedOrthogonalChannel = channel


    print("Channel="+str(channel)+channelToFreq(channel)+", Load="+str(load))

print "Least Loaded Channel = " + str(leastLoadedChannel) + channelToFreq(leastLoadedChannel)
print "Least Loaded Orthogonal Channel = " + str(leastLoadedOrthogonalChannel) + channelToFreq(leastLoadedOrthogonalChannel)

os._exit(leastLoadedOrthogonalChannel)