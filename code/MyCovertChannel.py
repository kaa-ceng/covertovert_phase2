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

    def send(self, log_file_name, src_ip, dst_ip, dst_port, min_packets, max_packets, delay_1_min, delay_1_max, delay_0_min, delay_0_max):
        """
        Creates a random binary message and then goes through each bit of this message. For each bit, it generates a random number of packets and sends them to the receiver.
        Whether the bit is 0 or 1, the delay is changed between the bursts. Therefore, on the receiver side, we can understand if it's 0 or 1 based on the delay.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for bit in binary_message:
            num_packets = self.random.randint(min_packets, max_packets)
            print(f"number of packets in burst: {num_packets}")
            for i in range(num_packets):
                start_time = time.time()
                packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
                super().send(packet)  # Use the send method from CovertChannelBase
                end_time = time.time()
                send_time = (end_time - start_time) 
                print(f"Packet {i} sent in {send_time:.5f} seconds")
            if bit == '1':
                delay = self.sleep_random_time_ms(delay_1_min, delay_1_max)
                print(f"Bit is 1, sleeping for {delay:.2f} milliseconds")
            elif bit == '0':
                delay = self.sleep_random_time_ms(delay_0_min, delay_0_max)
                print(f"Bit is 0, sleeping for {delay:.2f} milliseconds")
        packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
        super().send(packet)

    def receive(self, log_file_name, src_ip, dst_ip, port, threshold_0_min, threshold_0_max, threshold_1_min, threshold_1_max):
        packets = []
        last_time = 0

        def process_packet(packet):
            nonlocal last_time
            if packet.haslayer(TCP) and packet[IP].src == src_ip and packet[IP].dst == dst_ip and packet[TCP].dport == port:
                current_time = packet.time
                if last_time == 0:
                    last_time = current_time
                    print(f"Packet time: {current_time:.5f}")  # Debugging line to check the first packet time
                    return
                difference = current_time - last_time  # Convert send_time to seconds
                print(f"Packet time: {current_time:.5f}, Last time: {last_time:.5f}, Difference: {difference:.5f} seconds")  # Debugging line to check timing differences
                if threshold_0_min < difference < threshold_0_max:
                    packets.append('0')
                    last_time = current_time
                    print("Appended 0")  # Debugging line to check if '0' is appended
                elif threshold_1_min < difference < threshold_1_max:
                    packets.append('1')
                    last_time = current_time
                    print("Appended 1")  # Debugging line to check if '1' is appended
                else:
                    last_time = current_time

        sniff(
            iface="eth0",
            filter=f"tcp and src host {src_ip} and dst host {dst_ip} and dst port {port}",
            prn=process_packet
        )
        
        binary_message = ''.join(packets)
        print(f"Binary message: {binary_message}")  # Debugging line to check the binary message
        packet_string = ''.join(self.convert_eight_bits_to_character(binary_message[i:i+8]) for i in range(0, len(binary_message), 8))
        self.log_message(packet_string, log_file_name)