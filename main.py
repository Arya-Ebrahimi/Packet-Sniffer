from functions import *

if __name__ == '__main__':
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, src_address = connection.recvfrom(65536)
        dest_mac, src_mac, proto, data = frame(raw_data)
        
        print('dest: {}, src: {}, protocol: {}'.format(dest_mac, src_mac, proto))
        
        
