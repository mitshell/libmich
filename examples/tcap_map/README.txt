The map_message.py script has been contributed by Martin Kacer. Thanks to him !
More information can be found on his website: https://sites.google.com/site/h21lab/

The script has to be run from the command-line directly, e.g.:
'''
$ python ./map_messages.py 
MAP: 1274 objects loaded into GLOBAL
Input from: Standard input
Output to: map_messages.pcap
Output format: PCAP
Generate dummy Ethernet header: Protocol: 0x800
Generate dummy IP header: Protocol: 132
Generate dummy SCTP header: Source port: 2905. Dest port: 2905. Tag: 0
Generate dummy DATA chunk header: TSN: 0. SID: 0. SSN: 0. PPID: 0
Wrote packet of 162 bytes.
Wrote packet of 162 bytes.
[...]
Wrote packet of 162 bytes.
Wrote packet of 162 bytes.
Read 255 potential packets, wrote 255 packets (47678 bytes).
mich@LSF-TELECOM:~/src/libmich$ ls -l
total 388
drwxrwxr-x 3 mich mich  4096 May 11  2015 build
drwxrwxr-x 3 mich mich  4096 May 11  2015 examples
drwxrwxr-x 7 mich mich  4096 Sep  9  2015 libmich
-rw-rw-r-- 1 mich mich 18431 May 11  2015 license.txt
-rw-rw-r-- 1 mich mich 47678 Aug  5 10:22 map_messages.pcap
-rw-rw-r-- 1 mich mich 43823 Aug  5 10:21 map_messages.py
-rw-rw-r-- 1 mich mich   344 May 11  2015 preinstall.py
-rw-rw-r-- 1 mich mich 33106 Jun 15  2015 README_ASN1.md
-rw-rw-r-- 1 mich mich 23339 Aug  5 10:00 README.md
-rw-rw-r-- 1 mich mich  1240 Sep  1  2015 setup.py
-rw-rw-r-- 1 mich mich 98031 Aug  5 10:22 tmp.txt
mich@LSF-TELECOM:~/src/libmich$ wireshark map_messages.pcap &
'''

It creates a set of M3UA/SCCP/TCAP/MAP messages, scanning multiple MAP parameters, 
writes their hexadecimal representation into the tmp.txt file, 
and converts it into a pcap file, using some Linux and the text2pcap command.

