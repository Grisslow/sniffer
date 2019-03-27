import scapy.all as sa 


sa.sniff(prn=lambda x:x.show())
