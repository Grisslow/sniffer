import time
import math
import scapy.all as sa


TIME = time.gmtime()
PROTOCOLS = {}
FREQUENCY_OF_APPEARANCE = {6: 0.8,
                           17: 0.1,
                           58: 0.02,
                           2048: 0.01,
                           2: 0.01}


class Const:
    sens_coeff = 0.8


class Packet:
    count = 0
    normal_count = 10
    packet_kod = 0


def check_count(packet):
    if packet.count > packet.normal_count / Const.sens_coeff or \
            packet.count < packet.normal_count * Const.sens_coeff:
        print('DANGER! Too sharp change in traffic ' + str(packet.count))
    packet.normal_count = packet.count


def check_expected_value(packet):
    try:
        expected_value = packet.normal_count * FREQUENCY_OF_APPEARANCE[packet.packet_kod]
        standard_deviation = math.sqrt(
            (packet.normal_count ** 2) *
            FREQUENCY_OF_APPEARANCE[packet.packet_kod] -
            expected_value ** 2
        )

        if packet.count > expected_value + standard_deviation or \
                packet.count < expected_value - standard_deviation:
            print('DANGER! Mismatch with expectation')

    except KeyError:
        print('Unknown packet!')


def add_to_dict(prot):
    if not PROTOCOLS.get(prot):
        PROTOCOLS[prot] = Packet()
        PROTOCOLS[prot].packet_kod = prot
    else:
        PROTOCOLS[prot].count += 1


def check(x):
    global TIME
    ALL_PACKETS.count += 1

    if x.type == 34525:
        add_to_dict(x.nh)
    elif x.type == 2048:
        add_to_dict(x.proto)
    else:
        add_to_dict(x.type)

    time_now = time.gmtime()

    if time_now.tm_sec - TIME.tm_sec >= 30 or time_now.tm_min > TIME.tm_min:
        TIME = time.gmtime()
        check_count(ALL_PACKETS)
        ALL_PACKETS.count = 0

        for i in PROTOCOLS:
            check_count(PROTOCOLS[i])
            check_expected_value(PROTOCOLS[i])
            PROTOCOLS[i].count = 0


ALL_PACKETS = Packet()

sa.sniff(prn=check)
