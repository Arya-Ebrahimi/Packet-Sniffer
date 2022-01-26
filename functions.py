import socket
import struct
import binascii


#unpack frame from link layer
def frame(data):
    dest_mac, src_mac, proto=struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), proto, data[14:]

#format mac address in proper way that we use
def get_mac(bytes):
    str = map('{:02x}'.format, bytes)
    return ':'.join(str).upper()

#unpacks ipv4 packets
def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    
    header_length = (version_header_len & 15)*4
    
    title, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return version, header_length, title, proto, ipv4(src), ipv4(target), data[header_length:]


#format ipv4 address in proper way that we use (192.168.1.1
def ipv4(address):
    return '.'.join(map(str, address))


#icmp protocol unpack:
def icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#tcp protocol unpack:
def tcp(data):
    src_port, dest_port, seq, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12)*4
    flag_urg = (offset_flags & 32) >> 5
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8) >> 3
    flag_rst = (offset_flags & 4) >> 2
    flag_syn = (offset_flags & 2) >> 1
    flag_fin = offset_flags & 1
    flags = [flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin]
    return src_port, dest_port, seq, ack, flags, data[offset:]

#udp protocol unpack:
def udp(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def arp(data):
    (hardware_type, proto, hardware_size, proto_size,
    opcode, src_mac, src_ip, dest_mac, dest_ip) = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])

    return (hardware_type, proto, hardware_size, proto_size,
    opcode, get_mac(src_mac), ipv4(src_ip), get_mac(dest_mac), ipv4(dest_ip), data[28:])
    
    
