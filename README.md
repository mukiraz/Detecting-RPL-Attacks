# Comparison of Machine Learning Algorithms to Detect RPL-Based IoT Devices Vulnerability

## Purpose of Codes 

These python codes are used for the "Creating Data Set, Comparison of Machine Learning Algorithms, Experiments" section of my master's thesis (Comparison of Machine Learning Algorithms to Detect RPL-Based IoT Devices Vulnerability)
1. Making raw data meaningful,
2. Training the meaningful data with machine learning methods, and detecting the attack.

## General Information About the Thesis 

Detailed information can be found at [mukiraz.com](https://en.mukiraz.com)

### Thesis Abstract 

The RPL protocol (Routing Protocol for Low-Power and Lossy Networks) is a network protocol designed by IETF [Winter, et al. March 2012](https://www.hjp.at/doc/rfc/rfc6550.html) to optimize power consumption in the Internet of Things (IoT) devices. IoT devices have limited processing power, limited memory, and limited energy because they usually run on batteries. Designed to solve the energy problem in lossy networks, RPL aims to establish the shortest distance by creating a DAG (Directed Acyclic Graph) of n number of IoT devices over each other. Thus, it optimizes the energy expended. However, due to the complex infrastructure of the RPL protocol and the low capacity of IoT devices, this protocol is vulnerable to attacks. Therefore, it is crucial to develop a fast, practical, uncomplicated, and reliable intrusion detection system at the network layer. An anomaly will occur in layer three network packets in the event of an attack on RPL-powered IoT devices. Processing these packets with machine learning algorithms will make it extremely easy to detect the attack. [D'Hondt, Bahmad, Vanhee, & Sadre, 2015](https://github.com/dhondta/rpl-attacks) succeeded in simulating Flooding, Version Number Increase, and Decreased Rank Attacks. With the normal and malicious IoT motes that they created; the raw data sets of each attack were obtained. After the raw data sets were made meaningful, these data sets were separated as 1/3 test and 2/3 training data set. Datasets were trained and tested by "Decision Tree," "Logistic Regression," "Random Forest," "Naive Bayes," "K Nearest Neighbor," and "Artificial Neural Networks" algorithms. As a result of the comparison, the **Deep** Learning algorithm detected Flooding Attacks with a **97.2%** accuracy rate. The **K Nearest Neighbor** algorithm detected Version Number Increasing Attack with an **81%** accuracy rate. The **Deep Learning** algorithm detected decreased rank attacks with a **58%** accuracy rate.

**Keywords:**	RPL, Machine Learning, Flooding Attacks, Version Number Increase Attacks, Decreased Rank Attacks

## Actions Taken Before Using Codes 

The following steps have been followed to use these codes.

1.	Installing the Contiki Cooja IoT simulator on a computer with the Ubuntu 18.04 operating system. [Detailed Information](https://en.mukiraz.com/2022/06/contiki-operation-system-and-cooja/)

2.	Installation of the RPL Attacks Framework created by D'Hondt and others on a computer with another UBUNTU 18.04 operating system.  [Detailed Information](https://en.mukiraz.com/2022/06/dhondts-rpl-framework/)

3.	Creation of normal and vulnerable nodes with the RPL Attacks Business Framework created by D'Hondt and others. [Detailed Information](https://en.mukiraz.com/2022/06/obtaining-nodes/)

4.	Simulating with the Contiki Cooja IoT devices simulator with the created vulnerable and normal nodes, obtaining raw data and converting this raw data into a CVS file. [Detailed Information](https://en.mukiraz.com/2022/06/simulation-and-raw-data-2/)


With Contiki Cooja, we had 2 data sets created from the simulation with the weak node with the raw data set obtained from the simulation with normal nodes in the RPL Protocol. These two data sets will also have the following columns. 

**Source**

![Source](https://en.mukiraz.com/wp-content/uploads/2022/07/Source.png)

**Destination**

![Destination](https://en.mukiraz.com/wp-content/uploads/2022/07/Destination.png)

**Protocol**

![Protocol](https://en.mukiraz.com/wp-content/uploads/2022/07/Protocol.png)

**Length**

![Length](https://en.mukiraz.com/wp-content/uploads/2022/07/Length.png)

**Info**

![Info](https://en.mukiraz.com/wp-content/uploads/2022/07/Info.png)

## Python Codes Created to Make Sense of the Raw Data Set 

When we look at the CSV files of the raw data set, the information for each column is observed as follows.

No 	|	Time 	|	Source	|	Destination	|	Protocol 	Length	|	Info

The information obtained from the raw data set will not be enough to apply machine learning. The raw data obtained from simulations containing weak nodes is completely different from the raw data obtained from simulations containing normal motes.  It has been observed that this difference is the number of packets, message types, total packet lengths and rates. To detect this anomaly, the raw data is divided into 1-second frames. Within frames of each second, the following values were calculated, and a new data set was created.

- **Source Mote:** A unique number for each mote.
- **Destination Mote:** Same number as the source mote.
- **Packet Count:** The count of the whole source motes in the 1-second frame.
- **Source Mote Ratio:** (Source Mote Count/Packet Count).
- **Destination Mote Ratio:** (Destination Mote Count/Packet Count).
- **Source Mote Duration:** The sum of all packet durations sent from source to destination in the 1-second frame.
- **Destination Mote Duration:** The sum of all packet durations received by the destination in the 1-second frame.
- **Total Packet Duration:** It is the sum of all packet durations in the 1-second frame.
- **Total Packet Length:** It is the sum of all packet lengths in the 1-second frame.
- **Source Packet Ratio:** (Sum of Source Packet lengths/ Total Packet Length).
- **Destination Packet Ratio:** (Sum of Dest. Packet lengths/ Total Packet Length).
- **DIO Message Count:** Count of DIO messages in the 1-second frame.
- **DIS Message Count:** Count of DIS messages in the 1-second frame.
- **DAO Message Count:** Count of DAO messages in the 1-second frame
- **Other Message Count:** Count of the messages except for DIO, DIS, and DAO.
- **Label:** 0 or 1 (If the raw dataset has malicious mote/s, the label is 1 else 0).

The algorithm created to perform the above calculations is given below.

```
START
	Dset=INPUT(RawDataset)
	WHILE Dset Rows Ends
		Duration=time(current_row)-time(previous_row)
		Duration_list=APPEND(Duration)
	ENDWHILE
	
	Dset = Dset + Duration_list
	
	IP_dictionary={IP_Adress :unique_number}
	Crr_scnd=60
	Counter=0
	
	fs=FLOOR(Dset[Duration_list])
	
	WHILE counter < frame_second
		osf= GET(Dset[Time]>= fs and Dset[Time]<= Crr_scnd+1)
		WHILE osf Rows Ends:
			Osf_list=[ src=IP_dictionary[Source IP_Adress],
									dst=IP_dictionary[Dest. IP_Adress],
									pct_cnt=COUNT(rows)
									src_mote_rt= COUNT(src)/pct_cnt
									dst_mote_rt= COUNT(dst)/pct_cnt
									src_mote_dur=SUM(src_duration)
									dst_mote_dur= SUM(dst_duration)
									ttal_pckt_dur= SUM(duration)
									ttal_pckt_lngth= SUM(pckt_lngth)
									src_pckt_rt= SUM(src_pckt_lngth)/ ttal_pckt_lngth
									dst_pckt_rt= SUM(dst_pckt_lngth)/ ttal_pckt_lngth
									dio_msg_cnt= COUNT(dio_messages)
									dis_msg_cnt= COUNT(dis_messages)
									dao_msg_cnt= COUNT(dao_messages)
									other_msg_cnt= COUNT(other_messages)
									IF Dset=”Normal”
										Label=0
									ELSE
										Label=1
									ENDIF								
		ENDWHILE
	New_dset=APPEND(Osf_list)
	ENDWHILE
END
```
The python codes of this pseudocode  are contained in the Making_Data_Meaningful.py file.

During the simulation, it was observed that a system consisting of 12 nodes fully formed the DODAG structure after the 30th second. Due to the nature of RPL, when DODAG is occurring, devices will send DIO, DAO, and DAO-ACK messages to each other, and packet traffic will be different from the traffic after DODAG occurs. In order to prevent this difference from being learned by the machine, the data after the 60th second of the raw data set is taken and the new data set is created. 
The data sets created for each attack and classified as vulnerable-normal have become ready to be compared with different machine learning algorithms. As a result, a total of 3 data sets were created: Overflow Attacks data set, Reduced Rank attacks data set and Version Number Boost Attacks data set.

The data sets created for each attack and classified as vulnerable-normal have become ready to be compared with different machine learning algorithms. As a result, a total of 3 data sets were created: Overflow Attacks data set, Reduced Rank attacks data set and Version Number Boost Attacks data set.

## Analysis of the Made Sense Data Set with Machine Learning


The raw data sets were made meaningful and classified as normal and vulnerable. Even before machine learning was performed, an equal amount of rows were taken from normal and vulnerable data sets. For this, the number of rows of the data set with the least number of rows from the normal or vulnerable data sets obtained from the 60th second was taken as the basis, and the same amount of sales was taken from the other data set. Thus, it is aimed to obtain a balanced amount of data. Source and destination IP addresses are extracted from the datasets before the normalization process so that the machine does not learn whether there is an attack based on the source and destination IP addresses. Subsequently, the data were normalized. The normalization process of the test has been done with the StandardScaler library in python.

Subsequently, the dataset was split into test and training datasets in the amount of 2/3. (2/3 training, 1/3 testing).

After this stage, the data sets will be trained and tested with different machine learning algorithms and the most appropriate machine learning algorithm to be used in the detection of Flooding, Version Number Increase and Decreased Rank Attacks will be determined in the RPL protocol. For this purpose, six types of machine learning algorithms were tested. These are the algorithms Logistic Regression Classification, Decision Trees, Random Forest, Navie Bayes, KNN Classifier and Artificial Neural Networks.The parameters applied to machine learning are shown in Table-3.4.


| Algorithm  | Parameter |
| ------------- | ------------- |
| **Logistic Regression** | **Library:** sklearn.linear_model, LogisticRegression.  The existing parameters of the library are used. |
| **Random Forest** | **Library:** sklearn.ensemble, RandomForestClassifier.  **Parameters:** n_estimators=8, criterion='entropy' |
| **Decision Trees** | **Library:** sklearn.tree, DecisionTreeClassifier.  **Parameters:** criterion='entropy' |
| **Navie Bayes** | **Library:** sklearn.naive_bayes, GaussianNB.  The existing parameters of the library are used. |
| **KNN Classifier** | Library: sklearn.neighbors, KNeighborsClassifier.  The existing parameters of the library are used. |
| **Artificial Neural Networks** | **Library:** tensorflow, keras.  A 6-layer structure was applied. Neron numbers:26,52,56,13,7,1 Optimizer:"Nadam"; Again:60; Estimate threshold:0.7  |

After the execution of the experiments, the accuracy rate and training time will be compared on the values.
The accuracy rate (AR) is calculated as below, and TP is True Positive, TN is True Negative, FP is False Positive, and FN is False Negative.

AR = (TP +FP) / (TP + FP + TN + FN)

After the experiments are executed, the number of rows of data sets for Overflow attack, Version Number Boost Attack, Reduced Rank Attack, accuracy rate and training time values are shown in the table below. After training the data set with machine learning algorithms, of course, the detection of the error rate will take a shorter time. However, in this thesis study, it is aimed to analyze the data sets of the same attacks with different machine learning algorithms and to determine the fastest, most effective, uncomplicated and reliable algorithm among these algorithms. Therefore, the algorithm that performs the training in a shorter time and can detect the attack with high accuracy will be more cost-effective. The results of the attacks are interpreted below.


| 1  | 2 | 3 | 4 | 5 | 6 |
| ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
| Flooding Attacks (Hello Flood Attack) | B:214 <br> M:1259 <br> S:1473 | B:214 <br> M:214 <br> S:428 | Logistic Regression <br> Decision Trees <br> Random Forest <br> Naive Bayes <br> K Nearest Neighbor <br> Artificial Neural Networks | 95,7 <br> 93,6 <br> 95,0 <br> 69,7 <br> 95,7 <br> 97,2 | 363 <br> 0 <br> 168 <br> 13 <br> 4 <br> 1847 |
| Version Number Increase Attack | B:168 <br> M:1114 <br> S:1282 | B:168 <br> M:168 <br> S:336 | Logistic Regression <br> Decision Trees <br> Random Forest <br> Naive Bayes <br> K Nearest Neighbor <br> Artificial Neural Networks | 74,8 <br> 74,8 <br> 72,9 <br> 74,8 <br> 81,0 <br> 72,0 | 185 <br> 2 <br> 253 <br> 5 <br> 2 <br> 1688 |
| Decreased Rank Attack | B:160 <br> M:151 <br> S:311 | B:151 <br> M:151 <br> S:302 | Logistic Regression <br> Decision Trees <br> Random Forest <br> Naive Bayes <br> K Nearest Neighbor <br> Artificial Neural Networks | 54,0 <br> 57,0 <br> 58,0 <br> 54,0 <br> 56,0 <br> 58,0 | 5 <br> 2 <br> 10 <br> 1 <br> 0 <br> 1720 |

### Table Columns

1. Attack Type
2. Data Set Row Count
3. Test and Training Data Set Row Count
4. Algorithm
5. Accuracy Rate (%)
6. Training Time (ms)

### Table Synonyms

**B:** Dataset with benign motes row count 
**M:** Dataset with malicious motes row count
**S:** Sum of the row counts



