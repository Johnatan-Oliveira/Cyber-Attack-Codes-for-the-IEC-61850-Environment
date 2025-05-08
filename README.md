# Cyber-Attack-Codes-for-the-IEC-61850-Environment

## Overview

This repository contains scripts and configuration files used in academic research focused on the modeling and detection of cyberattacks in digital substations based on the IEC 61850 GOOSE protocol. The study aims to evaluate machine learning and deep learning-based intrusion detection systems (IDS) using datasets generated from realistic testbed simulations.

## Use of libiec61850

This repository relies on the libiec61850 (https://libiec61850.com/)) open-source library to generate and transmit GOOSE messages. This library was developed by Michael Zillgith, and it is licensed under the GPLv3 (GNU General Public License version 3).

## Attack Scenarios

The repository includes the implementation of four distinct types of cyberattacks:

**Replay Attack**: Captures and stores legitimate GOOSE trip commands during real electrical faults, and retransmits them at later times to maliciously trigger circuit breaker openings.

**Message Injection Attack**: Generates GOOSE messages without correct stNum/sqNum values. These messages are crafted manually to command breaker openings without relying on previously captured messages.

**Masquerade Attack**: The most complex attack, where bursts of forged GOOSE messages simulate legitimate trip commands by incrementing stNum and resetting sqNum, closely mimicking real electrical events.

**High-Rate Poisoning Attack**: Performs a denial-of-service (DoS)-like attack by flooding the network with thousands of GOOSE messages in a short time, overwhelming legitimate IED communication.

All attack simulations assume that the attacker has already gained access to the process-level operational network. The focus of the work is on modeling and detection—not on the earlier phases of cyber intrusion.

## Simulation Environment

Real-time simulation using RTDS for power system events.

Physical IEDs and a Windows 11 laptop used as the attacker device.

Traffic capture using Wireshark for GOOSE message streams.


This repository is provided for academic and research use only. If you use this work in your research, please cite the original paper and this repository.
