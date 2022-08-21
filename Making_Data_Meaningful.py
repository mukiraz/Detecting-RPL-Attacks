# -*- coding: utf-8 -*-
"""
Created on Fri Feb 19 11:42:08 2021

These codes were created for my master's thesis "Comparison of Machine Learning Algorithms to Detect RPL-Based IoT Devices Vulnerability".

See README file for details.

Basically, the program gets the RAW data of RPL network packets with this columns:

No 	|	Time 	|	Source	|	Destination	|	Protocol 	Length	|	Info

Then it splits the dataset into 1 second frames.
For each frame it calculates the columns below:

second | src | dst | packetcount | src_ratio | dst_ratio | src_duration_ratio | dst_duration_ratio | TotalPacketDuration | TotalPacketLenght | src_packet_ratio | dst_packet_ratio | DioCount | DisCount | DaoCount | OtherMsg | label


@author: Murat Ugur KIRAZ
"""
#libraries
import pandas as pd
import numpy as np

#Let's get the CSV file.
flnm = "HF-10N1R.csv"
filestr = "Attack Files/" + flnm


"""
When giving names to the CSV files, I made the following coding.

HF: Hello Flood,
DR: Decreased Rank,
VI: Version Number Increase,

R: Root,
N: Normal,
M: Malicious,

Numbers: Node Counts

For example

HF-1R10N1M

Hello Flood Attack with 1 root mote, 10 normal motes and 1 vulnerable mote

"""

#For machine learning, we are classifying the dataset wit 0 and 1. 0 means all motes are normal. 1 means it includes a malicious mote.
if "M" in flnm:
    lbl = 1
else:
    lbl = 0

# resultfile variable is used for recording pruduct CSV dataset.
resultfile = "Results/" + flnm

# We take raw data to the Raw_Data dataset.
Raw_Data = pd.read_csv(filestr , index_col = "No.")

# Converting Raw_Data to numpy array
np_Raw_Data = np.array(Raw_Data)

# Sorting data on 0 axis.(0 axis is the time values.)
# The columns 0: Time, 1: Source, 2:Destination, 3:Protocol, 4:Packet Length, 5:Info
np_Raw_Data = np_Raw_Data[np.argsort(np_Raw_Data[:, 0])]

# packetDurations list is used for calculating packet durations. With the while loop below, 
# we substracted two values np_Raw_Data[n][0] - np_Raw_Data[n - 1][0] and appended to the 
# packetDurations list.
packetDurations = []
counter = 0
while counter < len(np_Raw_Data):
    duration = 0
    if counter != 0 and counter + 1 <  len(np_Raw_Data):
        duration = np.float32(np_Raw_Data[counter][0])-np.float32(np_Raw_Data[counter - 1][0])
    packetDurations.append(duration) 
    counter +=  1

# We delete the first row of packetDurations
packetDurations = np.delete(packetDurations, 0, axis = 0)

# We delete the last row of np_Raw_Data
np_Raw_Data = np.delete(np_Raw_Data,len(np_Raw_Data)-1,axis = 0)

# We add  packetDurations column to the np_Raw_Data as 1st column.
# The columns 0: Time, 1:Packet Durations, 2: Source, 3:Destination, 4:Protocol, 5:Packet Length, 6:Info
np_Raw_Data = np.insert(np_Raw_Data, 1, packetDurations, axis = 1)

# source_unique_array variable contains unique values of source IP addresses.
source_unique_array = np.unique(np.array(Raw_Data.iloc[:,1:2].astype(str)))

# destination_unique_array variable contains unique values of destination IP addresses.
destination_unique_array = np.unique(np.array(Raw_Data.iloc[:,2:3].astype(str)))

# info_unique_array variable contains unique values of info colunm.
info_unique_array = np.unique(np.array(Raw_Data.iloc[:,5:6]))

# protocol_unique_array variable contains unique values of protocol column.
protocol_unique_array = np.unique(np.array(Raw_Data.iloc[:,3:4]))

# all_ip_addresses variable contains unique values of all IP addresses.
all_ip_addresses = np.concatenate((source_unique_array,destination_unique_array))
all_ip_addresses = np.unique(all_ip_addresses)

# ip_dict dictionary will hold the IPV6:IP Number key value pairs.
# example fe80::c30c:0:0:1 : 0
ip_dict = {}

# Here we used sklearn labelEncoder to give numbers to the ip addresses.
from sklearn import preprocessing
le = preprocessing.LabelEncoder()
lb_all_ip_addresses = le.fit_transform(all_ip_addresses)

# with the for loop we added Ip address key value pairs.
cnt = 0
for x in all_ip_addresses:
    ip_dict[x] = lb_all_ip_addresses[cnt]
    cnt  += 1

# Sorting data on 0 axis.(0 axis is the time values.)
np_Raw_Data = np_Raw_Data[np.argsort(np_Raw_Data[:, 0])]

# duration variable is the last second of time column.
duration = np.floor(np.float32(np_Raw_Data[-1][0]))

# Variables that are used for calculating values.
counter = 0
currentSecond = 60.0
packetcount = {}
TotalPacketDuration = {}
TotalPacketLenght = {}
src_count = {}
dst_count = {}
src_duration = {}
dst_duration = {}
src_packet_lenght_sum = {}
dst_packet_lenght_sum = {}
DioCount = {}
DisCount = {}
DaoCount = {}
OtherMsg = {}
frame = []

#Create an empty pandas dataframe with the columns.

row = pd.DataFrame(columns = ['second','src', 'dst','packetcount','src_ratio', 'dst_ratio','src_duration_ratio', 'dst_duration_ratio','TotalPacketDuration','TotalPacketLenght','src_packet_ratio','dst_packet_ratio','DioCount','DisCount','DaoCount','OtherMsg','label'])

while counter < duration:  
    
    # one_second_frame variable holds rows for 1 second duration.
    one_second_frame = np_Raw_Data[np.where(np.logical_and(np_Raw_Data[:, 0] >= currentSecond, np_Raw_Data[:, 0] <= currentSecond + 1.0))]
    
    # if there is data in the one_second_frame, make calculations.
    if one_second_frame.size > 1:
        # clear all variables.
        packetcount.clear()
        TotalPacketDuration.clear()
        TotalPacketLenght.clear()
        DioCount.clear()
        DisCount.clear()
        DaoCount.clear()
        src_duration.clear()
        dst_duration.clear()
        totalpackets = 0
        frame_packet_length_sum = 0
        total_duration = 0.0
        src_packet_lenght_sum.clear()
        dst_packet_lenght_sum.clear()
        src_count.clear()
        dst_count.clear()
        
        # looping in each one_second_frame row
        for packet in one_second_frame:
            # IEEE 802.15.4 protocols or Ack messages do not have no IP addresses and they are null. We will not process this data.
            if not pd.isnull(packet[2]):
                # src_dst variable is string and it holds the value of source and destination value like fe80::c30c:0:0:3-fe80::c30c:0:0:1
                src = packet[2]
                dst = packet[3]
                src_dst  =  src + "-" + dst
                
                # packetcount dictionary holds the "src_dst : count" key value pairs. (How many packey counts do we have source to destination?)
                packetcount[src_dst]  =  1 if src_dst not in packetcount else packetcount[src_dst] + 1
                
                # TotalPacketDuration dictionary holds the "src_dst : duration" key value pairs. (It is the sum of all packet durations from source to destination in the 1-second frame.)
                TotalPacketDuration[src_dst] = packet[1] if src_dst not in TotalPacketDuration else TotalPacketDuration[src_dst] + packet[1]
                
                # TotalPacketLenght dictionary holds the "src_dst : length" key value pairs. (It is the sum of all packet lengths from source to destination in the 1-second frame.)
                TotalPacketLenght[src_dst] = packet[5] if src_dst not in TotalPacketLenght else TotalPacketLenght[src_dst] + packet[5]
                
                # src_count dictionary holds the "source : count" key value pairs. (How many source IP adress has in 1 second frame?)
                src_count[src] = 1 if src not in src_count else src_count[src] + 1
                
                # dst_count dictionary holds the "destination : count" key value pairs. (How many destination IP adress has in 1 second frame?)
                dst_count[dst] = 1 if dst not in dst_count else dst_count[dst] + 1
                
                # src_duration dictionary holds the "source : duration" key value pairs. (What is the duration of source IP address in 1 second frame?)
                src_duration[src] = packet[1] if src not in src_duration else src_duration[src] + packet[1]
                
                # dst_duration dictionary holds the "destination : duration" key value pairs. (What is the duration of destination IP address in 1 second frame?)
                dst_duration[dst] = packet[1] if dst not in dst_duration else dst_duration[dst] + packet[1]
                
                # total_duration will be used for calculating ratios in a one second frame
                total_duration += packet[1]
                
                # src_packet_lenght_sum dictionary holds "source : source_packet_length_sum" key value pairs.
                src_packet_lenght_sum[src] = packet[5] if src not in src_packet_lenght_sum else src_packet_lenght_sum[src] + packet[5]
                
                 # dst_packet_lenght_sum dictionary holds "destination : destination_packet_length_sum" key value pairs.
                dst_packet_lenght_sum[dst] = packet[5] if dst not in dst_packet_lenght_sum else dst_packet_lenght_sum[dst] + packet[5]
                
                # frame_packet_length_sum will be used for calculating ratios in a one second frame
                frame_packet_length_sum +=  packet[5]
                
                # totalpackets will be used for calculating ratios in a one second frame
                totalpackets +=  1
                
                # DIO, DIS, DAO messages counts.
                if packet[6]=="RPL Control (DODAG Information Object)":
                    DioCount[src_dst] = 1 if src_dst not in DioCount else DioCount[src_dst] + 1
                if packet[6]=="RPL Control (DODAG Information Solicitation)":
                    DisCount[src_dst] = 1 if src_dst not in DisCount else DisCount[src_dst] + 1
                if packet[6]=="RPL Control (Destination Advertisement Object)":
                    DaoCount[src_dst] = 1 if src_dst not in DaoCount else DaoCount[src_dst] + 1
                if ((packet[6]!="RPL Control (Destination Advertisement Object)") and (packet[6]!="RPL Control (DODAG Information Object)") and (packet[6]!="RPL Control (Destination Advertisement Object)")) :
                    OtherMsg[src_dst] = 1 if src_dst not in OtherMsg else OtherMsg[src_dst] + 1
       
        # this for loop calculates the ratios.
        for i in packetcount:
            if not i in DioCount:
                arr_diocount = 0
            else:
                arr_diocount = DioCount[i]
            if not i in DisCount:
                arr_discount = 0
            else:
                arr_discount = DisCount[i]
            if not i in DaoCount:
                arr_daocount = 0
            else:
                arr_daocount = DaoCount[i]
            if not i in OtherMsg:
                arr_orhermsg = 0
            else:
                arr_orhermsg = OtherMsg[i]
                
            # Splitting source and destination
            x = i.split("-")
            sourcee = x[0]
            destinatt = x[1]
            
            # calculating the source ratio in 1 second frame
            src_ratio = src_count[sourcee]/totalpackets
            
            # calculating the destination ratio in 1 second frame
            dst_ratio = dst_count[destinatt]/totalpackets
            
            # calculating the source duration ratio in 1 second frame
            src_duration_ratio = src_duration[sourcee]/total_duration
            
            # calculating the destination duration ratio in 1 second frame
            dst_duration_ratio = dst_duration[destinatt]/total_duration
            
            # calculating the source duration ratio in 1 second frame
            src_packet_ratio = src_packet_lenght_sum[sourcee]/frame_packet_length_sum
            
            # calculating the destination duration ratio in 1 second frame
            dst_packet_ratio = dst_packet_lenght_sum[destinatt]/frame_packet_length_sum
            
            #establishing an array for adding the calculations to the row of row dataframe.
            # the columns are: 
            # 'second',
            # 'src', 
            # 'dst',
            # 'packetcount',
            # 'src_ratio', 
            # 'dst_ratio',
            # 'src_duration_ratio', 
            # 'dst_duration_ratio',
            # 'TotalPacketDuration',
            # 'TotalPacketLenght',
            # 'src_packet_ratio',
            # 'dst_packet_ratio',
            # 'DioCount',
            # 'DisCount',
            # 'DaoCount',
            # 'OtherMsg',
            # 'label'
            array = np.array([
                np.single(currentSecond),
                ip_dict[sourcee],
                ip_dict[destinatt],
                int(packetcount[i]),
                np.single(src_ratio),
                np.single(dst_ratio),
                np.single(src_duration_ratio),
                np.single(dst_duration_ratio),
                TotalPacketDuration[i],
                TotalPacketLenght[i],
                np.single(src_packet_ratio),
                np.single(dst_packet_ratio),
                arr_diocount,
                arr_discount,
                arr_daocount,
                arr_orhermsg,
                lbl], dtype="object")
            a_series = pd.Series(array, index = row.columns)            
            row = row.append(a_series, ignore_index=True)
            
    # increase second 1
    currentSecond += 1.0
    
    # increase counter 1
    counter +=  1
    
    # print data for observing the process.
    print(str(counter) + " of " + str(duration) + " of process is ok!!!")

#Save as CSV file
row.to_csv(resultfile, index = False, sep = ";")

