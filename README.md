# Pcap Replayer
A simple pcap replay attack written in C
Written as a PoC for UNIX Security.

Usage: replayer [-s] <configuration file>
       [-s - Send packets to config victim]
         configuration file format
            <client mac>
            <tcpdump log file>
            <victim ip>
            <victim mac>
            <victim port>
            <attacker ip>
            <attacker mac>
            <attacker port>
            <replay victim ip>
            <replay victim mac>
            <replay victim port>
            <replay attacker ip>
            <replay attacker mac>
            <replay attacker port>
            <interface>
            <timing>

NOT INTENDED FOR ILLEGAL OR MALICIOUS USE.
