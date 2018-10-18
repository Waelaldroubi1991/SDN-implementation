# SDN

## Introduction
SDN is a new approach to the current world of networking, in this lab you will learn basic concepts of SDN through OpenFlow. OpenFlow started with several engineers from Stanford University creating a protocol that would have a logically centralised control plane separated from the underlying switching details. OpenFlow was architected for a number of devices containing only data planes to respond to commands sent to them from a logically centralised controller that housed the single control plane for that network. The controller is responsible for maintaining all of the network paths, as well as programming each of the network devices it controlled. The commands and responses to those commands are described in the OpenFlow protocol.

## Background reading
Before starting this lab, read up on the technologies you will be using:
- The SDN emulation environment, mininet (30 minutes – 1 hour) Link: http://mininet.org/sample-workflow/
- Refresh your Python programming skills. (1 hour +) Link: http://docs.python.org/tutorial/
- Study the Ryu tutorial (~ 2 hours) Link: http://sdnhub.org/tutorials/ryu/

## Requirements
- Key Task 1
Modify simple_switch.py to include logic to block IP traffic between host 2 and host 3.

- Key Task 2
Extend simple_switch.py to count all traffic going to and originating at host 1.

- Key Task 3
Create a rule in simple_switch.py that routes messages to the controller for topology maintenance.
HINT: Ryu’s topology viewer uses LLDP to visualise routes, you will need to create a simple database application to maintain routes and then trap LLDP messages to update the database. You may assume a single database and do not need to address any concurrency issues.
Please see the attachment "Topology_Discovery_with_Ryu.pdf" for more information.

NOTES:
All the files in "ryu" are created by "root", it's better to change the directory owner by the following commands under "/home/mininet" before any modification. Otherwise, all the files under ryu cannot be edited by the user "nwen302".

$sudo chown -R nwen302:nwen302 ryu
