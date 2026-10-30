from struct import *
import packet_struct
import sys

class pcaprec_hdr_s:
    def __init__(self, ts_sec, ts_usec, incl_len, orig_len):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len

class Connection:
    def __init__(self,key):
        self.key = key
        self.packets = []

        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.state = "S0F0"

        self.is_complete = False
        self.start_time = 0.0
        self.end_time = 0.0
        self.duration = 0.0

        self.source_ip = None
        self.destination_ip = None
        self.source_port = None
        self.destination_port = None

    def add_packet(self, packet):
        self.packets.append(packet)

    def analyze_state(self):
        for packet in self.packets:
            flags = packet.TCP_header.flags

            if flags.get("SYN") == 1:
                self.syn_count += 1
                if self.syn_count == 1:
                    self.start_time = packet.timestamp
            
            if flags.get("FIN") == 1:
                self.fin_count += 1
                self.end_time = packet.timestamp

            if flags.get("RST") == 1:
                self.rst_count += 1

        self.state = f"S{self.syn_count}F{self.fin_count}/R" if self.rst_count > 0 else f"S{self.syn_count}F{self.fin_count}"

        if self.syn_count >= 1 and self.fin_count >= 1:
            self.is_complete = True
            self.duration = round(self.end_time - self.start_time, 6)

    def calculate_metrics(self):

        self.source_ip = self.packets[0].IP_header.src_ip
        self.destination_ip = self.packets[0].IP_header.dst_ip
        self.source_port = self.packets[0].TCP_header.src_port 
        self.destination_port = self.packets[0].TCP_header.dst_port 
        
        # Only process completed connections
        if not self.is_complete:
            return

        # Identify the source IP. Provides the direction of packets
        client_ip = self.packets[0].IP_header.src_ip

        self.src_to_dst_packets = 0
        self.dst_to_src_packets = 0
        self.src_to_dst_bytes = 0
        self.dst_to_src_bytes = 0
        self.window_sizes = []
        self.rtts = []

        # Hashmap of expected acknowledgements
        # Key: expected ACK number, Value: timestamp the sent data
        pending_acks = {}

        for packet in self.packets:

            # Calculate payload
            ip_total_len = packet.IP_header.total_len
            ip_header_len = packet.IP_header.ip_header_len
            tcp_header_len = packet.TCP_header.data_offset

            payload_size  = ip_total_len - ip_header_len - tcp_header_len

            # Determine the direction of the packet, increment counters accordingly
            if packet.IP_header.src_ip == client_ip:
                self.src_to_dst_packets += 1
                self.src_to_dst_bytes += payload_size
            else:
                self.dst_to_src_packets += 1
                self.dst_to_src_bytes += payload_size

            # Store window sizes
            self.window_sizes.append(packet.TCP_header.window_size)

            # Calculate RTT 
            seq_num = packet.TCP_header.seq_num
            ack_num = packet.TCP_header.ack_num
            flags = packet.TCP_header.flags

            # Check if packet is an ACK
            if flags.get("ACK") == 1 and ack_num in pending_acks and not packet.IP_header.src_ip == client_ip:
                
                rtt = packet.timestamp - pending_acks[ack_num]
                self.rtts.append(round(rtt,6))

                del pending_acks[ack_num]

            # Check if packet contains any data, wait for ACK

            if flags.get("SYN") == 1 or flags.get("FIN") == 1 and packet.IP_header.src_ip == client_ip:
                expected_ack = seq_num + 1
                if expected_ack not in pending_acks:
                    pending_acks[expected_ack] = packet.timestamp
    
def parse_global_header(file):
        # Global Header

        byte_order = '<'

        # Read global header
        global_header = file.read(24)
        if len(global_header) < 24:
            print("Error: File is too small to contain global header.")
            sys.exit(1)

        # Check endianness for swapped byte order
        if (global_header[0:4] in (b'\xa1\xb2\xc3\xd4')):
            byte_order = ">"
        elif (global_header[0:4] in (b'\xd4\xc3\xb2\xa1')):
            byte_order = "<"
        else:
            print(f"Error: Extracted magic number {global_header[0:4]} is not known")
        
        # Unpack the header
        global_header_struct = unpack(f"{byte_order}IHHIIII",global_header)

        return byte_order

def parse_packet(file, byte_order):
    orig_time = None
    packets = 0
    parsed_tcp_packets = []

    header_format = byte_order + "IIII"

    while True:

        packet_header = file.read(16)

        if len(packet_header) < 16:
            break

        packets += 1

        # Unpack header
        ts_sec, ts_usec, incl_len, orig_len = unpack(header_format, packet_header)

        abs_time = ts_sec + (ts_usec * 0.000001)
        if orig_time is None:
                orig_time = abs_time

        ts_sec_bytes = packet_header[0:4]
        ts_usec_bytes = packet_header[4:8]

        packet_data = file.read(incl_len)

        # Check if packet is tcp 
        tcp_packet = check_tcp_and_process(packet_data, packets, ts_sec_bytes, ts_usec_bytes, orig_time)
        if tcp_packet is not None:
            parsed_tcp_packets.append(tcp_packet)   
    return parsed_tcp_packets


def check_tcp_and_process(packet_data, packet_count, ts_sec_bytes, ts_usec_bytes, orig_time):
    # 1. Check if packet contains both Ethernet and IP

    if len(packet_data) < 34:
        return None
    
    protocol_offset = 14 + 9
    protocol_val = unpack('B', packet_data[protocol_offset: protocol_offset + 1])[0]

    if protocol_val != 6:
        return None

    # Initialize packet_struct obj
    current_packet = packet_struct.packet()
    current_packet.packet_No_set(current_packet)
    current_packet.timestamp_set(ts_sec_bytes, ts_usec_bytes, orig_time)

  
    ip_header_start = 14

    # IP header length
    current_packet.IP_header.get_header_len(packet_data[ip_header_start: ip_header_start + 1])
    ip_header_len = current_packet.IP_header.ip_header_len

    # Total IP length
    current_packet.IP_header.get_total_len(packet_data[ip_header_start + 2: ip_header_start + 4])

    # IP address of source and destination
    source_offset = 14 + 12
    IP_src = packet_data[source_offset: source_offset + 4]

    dest_offset = 14 + 12 + 4
    IP_dest = packet_data[dest_offset: dest_offset + 4]

    current_packet.IP_header.get_IP(IP_src, IP_dest)
    
    # Parse TCP header
    tcp_header_start = ip_header_start + ip_header_len

    if len(packet_data) < tcp_header_start + 20:
         return None

    # Source port
    current_packet.TCP_header.get_src_port(packet_data[tcp_header_start: tcp_header_start + 2])

    # Destination port
    current_packet.TCP_header.get_dst_port(packet_data[tcp_header_start + 2: tcp_header_start + 4])

    # Sequence number
    current_packet.TCP_header.get_seq_num(packet_data[tcp_header_start + 4: tcp_header_start + 8])

    # Acknowledgement number
    current_packet.TCP_header.get_ack_num(packet_data[tcp_header_start + 8: tcp_header_start + 12])

    # Data offset
    current_packet.TCP_header.get_data_offset(packet_data[tcp_header_start + 12: tcp_header_start + 13])

    # TCP Flags
    current_packet.TCP_header.get_flags(packet_data[tcp_header_start + 13: tcp_header_start + 14])

    #Window Size
    window_1 = packet_data[tcp_header_start + 14: tcp_header_start + 15]
    window_2 = packet_data[tcp_header_start + 15: tcp_header_start + 16]
    current_packet.TCP_header.get_window_size(window_1, window_2)
    
    return current_packet

def group_into_connections(parsed_tcp_packets):
    connection_dict = {}

    for packet in parsed_tcp_packets:
        src_ip = packet.IP_header.src_ip
        dst_ip = packet.IP_header.dst_ip
        src_port = packet.TCP_header.src_port
        dst_port = packet.TCP_header.dst_port

        if src_ip < dst_ip:
            key = (src_ip, src_port, dst_ip, dst_port)
        else:
            key = (dst_ip, dst_port, src_ip, src_port)

        if key not in connection_dict:
            connection_dict[key] = Connection(key)

        connection_dict[key].add_packet(packet)

    return connection_dict

def analyze_all_connections(connection_dict):
    complete_connections = []
    all_connections = []


    for key, conn in connection_dict.items():
        conn.analyze_state()
        all_connections.append(conn)

        if conn.is_complete:
            complete_connections.append(conn)

    return complete_connections, all_connections

def general(connection_list):
    # Number of reset TCP connections
    rst_connections = 0
    for conn in connection_list:
        if conn.rst_count > 0:
            rst_connections += 1
    return rst_connections

def complete_TCP_connections(complete_connection_list):
    total_time, mintd, meantd, maxtd = 0, -1, -1, -1
    total_rtt, minrtt, meanrtt, maxrtt = 0, -1, -1, -1
    rtt_count = 0
    total_pack, minpack, meanpack, maxpack = 0, -1, -1, -1
    total_win, minwin, meanwin, maxwin = 0, -1, -1, -1
    win_count = 0
    for conn in complete_connection_list:
        # Time duration calculation
        total_time += conn.duration
        mintd = conn.duration if conn.duration < mintd or mintd == -1 else mintd
        maxtd = conn.duration if conn.duration > maxtd or maxtd == -1 else maxtd
        
        # RTT calculation
        rtt_list = conn.rtts
        for rtt in rtt_list:
            total_rtt += rtt
            rtt_count += 1
            minrtt = rtt if rtt < minrtt or minrtt == -1 else minrtt
            maxrtt = rtt if rtt > maxrtt or maxrtt == -1 else maxrtt
                    
        # Packet calculation
        total_pack += len(conn.packets)
        minpack = len(conn.packets) if len(conn.packets) < minpack or minpack == -1 else minpack
        maxpack = len(conn.packets) if len(conn.packets) > maxpack or maxpack == -1 else maxpack
        

        # Window calculation
        win_list = conn.window_sizes
        for window in win_list:
            total_win += window
            win_count += 1
            minwin = window if window < minwin or minwin == -1 else minwin
            maxwin = window if window > maxwin or maxwin == -1 else maxwin
                    

    meantd = total_time/len(complete_connection_list)
    meanrtt = total_rtt/rtt_count if rtt_count > 0 else 0
    meanpack = total_pack/len(complete_connection_list)
    meanwin = total_win/win_count if win_count > 0 else 0
    return mintd, meantd, maxtd, minrtt, meanrtt, maxrtt, minpack, meanpack, maxpack, minwin, meanwin, maxwin
def main():
    
    filename = input("Enter .cap file name to be analyzed: ")
        
    # Step 1: open file and get byte order
    try:
        with open(filename, 'rb') as file:
            byte_order = '<'
            byte_order = parse_global_header(file)

        # Step 2: Parse packet header and extract timestamp

        # Step 3 & 4 Check TCP / non-TCP packet and part Ethernet, IP, TCP header
            return_parsed_tcp_packets = parse_packet(file, byte_order)

        # Step 5: Define connection
            returned_connection_dic = group_into_connections(return_parsed_tcp_packets)

        # Step 6: Connection dict
            returned_complete_conn, returned_all_conn = analyze_all_connections(returned_connection_dic)

        # Step 7: Calculate metrics: RTT, window, payload
            for conn in returned_all_conn:
                conn.calculate_metrics()

    except FileNotFoundError:
        print("Error: The file does not exist.")

    mintd, meantd, maxtd, minrtt, meanrtt, maxrtt, minpack, meanpack, maxpack, minwin, meanwin, maxwin = complete_TCP_connections(returned_complete_conn)

    conn_count = 0
    for conn in returned_all_conn:
        conn_count += 1
    print(f"A) Total number of connections: {conn_count}")
    print("__________________________________________________________________\n")
    print("B) Connection's details\n")
    conn_count = 1
    for conn in returned_all_conn:
        print(f"Connection {conn_count}:")
        print(f"Source Address: {conn.source_ip}")
        print(f"Destination Address: {conn.destination_ip}")
        print(f"Source Port: {conn.source_port}")
        print(f"Destination Port: {conn.destination_port}")
        print(f"Status: {conn.state}")
        if conn.fin_count > 0:
            print(f"Start time: {conn.start_time} seconds")
            print(f"End Time: {conn.end_time} seconds")
            print(f"Duration: {conn.duration} seconds")
            print(f"Number of packets sent from Source to Destination: {conn.src_to_dst_packets}")
            print(f"Number of packets sent from Destination to Source: {conn.dst_to_src_packets}")
            print(f"Total number of packets: {len(conn.packets)}")
            print(f"Number of data bytes sent from Source to Destination: {conn.src_to_dst_bytes}")
            print(f"Number of data bytes sent from Destination to Source: {conn.dst_to_src_bytes}")
            print(f"Total number of data bytes: {conn.src_to_dst_bytes + conn.dst_to_src_bytes}")
            print("END")
        print("++++++++++++++++++++++++++++++++")
        conn_count += 1
    print("________________________________________________")
    print("C) General\n")
    print(f"Total number of complete TCP connections: {len(returned_complete_conn)}")
    print(f"Number of reset TCP connections: {general(returned_all_conn)}")
    print(f"Number of TCP connections that were still open when the trace capture ended: {len(returned_all_conn) - len(returned_complete_conn)}")
    print(f"________________________________________________")
    print(f"D) Complete TCP connections\n")
    print(f"Minimum time duration: {mintd} seconds")
    print(f"Mean time duration: {meantd} seconds")
    print(f"Maximum time duration: {maxtd} seconds")
    print(f"\n")
    print(f"Minimum RTT value: {minrtt}")
    print(f"Mean RTT value: {round(meanrtt,6)}")
    print(f"Maximum RTT value: {maxrtt}")
    print(f"\n")
    print(f"Minimum number of packets including both send/recieve: {minpack}")
    print(f"Mean number of packet including both send/recieve: {meanpack}")
    print(f"Maximum number of packet including both send/recieve: {maxpack}")
    print(f"\n")
    print(f"Minimum recieve window size including both send/revieve: {minwin} bytes")
    print(f"Mean recieve window size including both send/recieve: {round(meanwin,6)} bytes")
    print(f"Maximum recieve window size including both send/recieve: {maxwin} bytes")
    print(f"________________________________________________")


if __name__ == '__main__':
    main()