<center> <h1>Simulation Report</h1> </center>

## Test hello-flood simulation

### 1. Introduction

**Goal**: Create a new simulation


### 2. Configuration

#### Wireless Sensor Network

The simulation lasts 120 seconds and is not repeated.

The WSN contains:

- 1 root node of type *root-echo* built upon a *Z1*
- 20 sensors of type *sensor-dummy* built upon a *Z1*
- 1 malicious mote of type *malicious-sensor* built upon a *Z1*

The sensors are spread across an area of 500 meters side and centered around the root node at a minimum distance of 20.0 meters and a maximum distance of 500 meters. They have a maximum transmission range of 50.0 meters and a maximum interference range of 100.0 meters.

The WSN configuration is depicted in Figures 1 and 2:

<div class="left">
  <figure>
    <img src="without-malicious/results/wsn-without-malicious_start.png" alt="ERROR">
    <figcaption>Fig 1 - WSN configuration without the malicious mote before starting the simulation.</figcaption>
  </figure> 
</div>
<div class="right">
  <figure>
    <img src="with-malicious/results/wsn-with-malicious_start.png" alt="ERROR">
    <figcaption>Fig 2 - WSN configuration with the malicious mote before starting the simulation.</figcaption>
  </figure> 
</div>

#### Attack

The attack is composed of the following building blocks:


- hello-flood



### 3. Results

In this section, the pictures on the left side corresponds to the results for the simulation without the malicious mote. These on the left are for the simulation with the malicious mote.

#### Resulting DODAG

The resulting Destination Oriented Directed Acyclic Graph (DODAG) is depicted in the following pictures:

<div class="left">
  <figure>
    <img src="without-malicious/results/dodag.png" alt="ERROR">
    <figcaption>Fig 3 - Final DODAG for the simulation without the malicious mote.</figcaption>
  </figure> 
</div><div class="right">
  <figure>
    <img src="with-malicious/results/dodag.png" alt="ERROR">
    <figcaption>Fig 4 - Final DODAG for the simulation with the malicious mote.</figcaption>
  </figure> 
</div>

<textarea>
Insert your comments here.
</textarea>

> **Important note**: The resulting DODAG's could be not representative if the duration is not long enough. Ensure that it is set appropriately.

#### Power Tracking Analysis

The power tracking is depicted in the following pictures:

<div class="left">
  <figure>
    <img src="without-malicious/results/powertracking.png" alt="ERROR">
    <figcaption>Fig 5 - Power tracking histogram for the simulation without the malicious mote.</figcaption>
  </figure> 
</div>
<div class="right">
  <figure>
    <img src="with-malicious/results/powertracking.png" alt="ERROR">
    <figcaption>Fig 6 - Power tracking histogram for the simulation with the malicious mote.</figcaption>
  </figure> 
</div>

<textarea>
Insert your comments here.
</textarea>
