import time
import random
from scapy.all import IP, TCP, sniff
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    Covert Timing Channel that exploits Idle Period Between Packet Bursts using TCP [Code: CTC-IPPB-TCP]
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        super().__init__()
        self.random = random
        self.is_dot = False

    def send(self, log_file_name, src_ip, dst_ip, dst_port, min_packets, max_packets, delay_0_min, delay_1_min):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16)
        start_time = time.time()
        for bit in binary_message:
            num_packets = self.random.randint(min_packets, max_packets)
            for _ in range(num_packets):
                packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
                super().send(packet)  # Use the send method from CovertChannelBase
            if bit == '1':
                time.sleep(delay_1_min)
            elif bit == '0':
                time.sleep(delay_0_min)
        end_time = time.time()  # End the timer
        packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
        super().send(packet) 

        # Calculate covert channel capacity
        time_taken = end_time - start_time
        capacity_bps = 128 / time_taken
        print(f"Covert channel capacity: {capacity_bps:.2f} bits per second")

    def receive(self, log_file_name, src_ip, dst_ip, port, threshold_0_min, threshold_0_max):
        packets = []
        last_time = 0
        self.is_dot = False
        i = 1
        
        def process_packet(packet):
            nonlocal last_time, i
            packet_string1 = ''

            current_time = packet.time
            if last_time == 0:
                last_time = current_time
                return
            difference = current_time - last_time
            print(f"Difference: {difference} seconds") 
            if threshold_0_min < difference < threshold_0_max:
                packets.append('0')
                print("Appended 0")  # Debugging line to check if '0' is appended
            elif threshold_0_max < difference:
                packets.append('1')
                print("Appended 1")  # Debugging line to check if '1' is appended
            last_time = current_time

            if(len(packets)== 8*i):
                    
                message = ''.join(packets[8*(i-1):8*i])
                packet_string1 = ''.join(self.convert_eight_bits_to_character(message))
                i = i+1
            if(packet_string1== '.'):
                self.is_dot = True

        sniff(
            iface="eth0",
            filter=f"tcp and src host {src_ip} and dst host {dst_ip} and dst port {port}",
            prn=process_packet,
            stop_filter= lambda packet: self.is_dot
        )
        

        binary_message = ''.join(packets)
        print(f"Binary message: {binary_message}")  # Debugging line to check the binary message
        packet_string = ''.join(self.convert_eight_bits_to_character(binary_message[i:i+8]) for i in range(0, len(binary_message), 8))
        self.log_message(packet_string, log_file_name)