from CovertChannelBase import CovertChannelBase
import random
from scapy.all import IP, TCP, sniff

class MyCovertChannel(CovertChannelBase):
    
    """
    Covert Timing Channel that exploits Idle Period Between Packet Bursts using TCP [Code: CTC-IPPB-TCP]
Responses: 0
Limit: 1
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        super().__init__()
        self.random = random
        
    def send(self, log_file_name, dst_ip, dst_port, min_packets, max_packets, delay_1_min, delay_1_max, delay_0_min, delay_0_max):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        "creates random binary message and then goes through each bit of this message. For each bit it generates a random number of packets and sends them to receiver."
        "whether bit is 0 or 1 delay is changed of the burst therefore on receiver side we can understand if its 0 or 1 based on the delay"
        
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for bit in binary_message:
            num_packets = self.random.randint(min_packets, max_packets)
            for i in range(num_packets):
                packet = IP(dst=dst_ip)/TCP(dport=dst_port)
                super().send(packet)  # Use the send method from CovertChannelBase
            if bit == '1':
                self.sleep_random_time_ms(delay_1_min, delay_1_max)
            elif bit == '0':
                self.sleep_random_time_ms(delay_0_min, delay_0_max)

    def receive(self, log_file_name, port, threshold_0_min=0.07, threshold_0_max=0.09, threshold_1_min=0.10, threshold_1_max=0.12):
        packets = []
        last_time = 0

        def process_packet(packet):
            nonlocal last_time
            if packet.haslayer(TCP) and packet[IP].src == "172.18.0.2" and packet[IP].dst == "172.18.0.3":
                current_time = packet.time
                difference = current_time - last_time
                print(f"Packet time: {current_time}, Last time: {last_time}, Difference: {difference}")  # Debugging line to check timing differences
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

        sniff(filter=f"tcp and port {port}", prn=process_packet, store=0)
        binary_message = ''.join(packets)
        print(f"Binary message: {binary_message}")  # Debugging line to check the binary message
        packet_string = ''.join(self.convert_eight_bits_to_character(binary_message[i:i+8]) for i in range(0, len(binary_message), 8))
        self.log_message(packet_string, log_file_name)