from functions import *

if __name__ == '__main__':
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, src_address = connection.recvfrom(65536)
        dest_mac, src_mac, protocol, data = frame(raw_data)
        #link layer
        print('link layer:')
        print('dest mac: {}, src mac: {}, protocol: {}'.format(dest_mac, src_mac, protocol))
        
        #network layer protocols:
        #8 is ethernet
        if protocol == 8:
            print('\tnetwork layer:')
            version, header_length, title, net_protocol, src, target, data = ipv4_packet(data)
            print('\tversion: {}, title(ttl): {}, proto: {}, src: {}, target: {}'
                  .format(version, title, net_protocol, src, target))
            
            #transport layer protocols:
            if net_protocol == 6:
                #tcp

                print('\t\ttransport layer (tcp segment)')
                src_port, dest_port, seq, ack, flags, data = tcp(data)
                
                print('\t\tsrc port: {}, dest port: {}, seq: {}, ack: {}, flags: {}'
                  .format(src_port, dest_port, seq, ack, flags))
                print('\t\tdata:')
                print(data)
            
            elif net_protocol == 1:
                #icmp
                
                print('\t\ttransport layer (icmp segment)')
                icmp_type, code, checksum, data = icmp(data)
                
                print('\t\ticmp type: {}, code: {}, checksum: {}:'
                  .format(icmp_type, code, checksum))
                print('\t\tdata:')
                print(data)
                
            elif net_protocol == 17:
                #udp
                
                print('\t\ttransport layer (udp segment)')
                src_port, dest_port, size, data = udp(data)
                
                print('\t\tsrc port: {}, dest port: {}, size: {}'
                  .format(src_port, dest_port, size))
                print('\t\tdata:')
                print(data)