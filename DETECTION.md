# ARP Detection Guide

## Overview
ARP monitoring and attack detection techniques.

## ARP Attacks

### ARP Spoofing
- MAC address poisoning
- Man-in-the-middle setup
- Gateway impersonation
- Client targeting

### ARP Cache Poisoning
- Gratuitous ARP abuse
- Static entry manipulation
- Proxy ARP attacks
- VLAN hopping setup

## Detection Methods

### Passive Monitoring
- ARP table snapshots
- MAC-IP correlation
- Timing analysis
- Packet rate monitoring

### Active Detection
- ARP probe requests
- Duplicate IP detection
- MAC validation
- Gateway verification

## Alert Triggers

### Immediate Alerts
- New MAC for existing IP
- Gateway MAC change
- Broadcast storms
- Unusual ARP rates

### Correlation Alerts
- Multiple MAC flapping
- Network scan patterns
- Rogue DHCP indicators

## Response Actions
- Email notification
- SNMP traps
- Firewall updates
- Switch port disable

## Configuration
- Baseline learning
- Whitelist management
- Alert thresholds
- Log retention

## Legal Notice
For authorized network security.
