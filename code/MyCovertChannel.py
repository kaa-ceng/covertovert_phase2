from CovertChannelBase import CovertChannelBase
import random
from scapy.all import IP, TCP

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
        
        pass
    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        "creates random binary message and then goes through each bit of this message. For each bit it generates a random number of packets and sends them to receiever."
        "whether bit is 0 or 1 delay is changed of the burst therefore on receiver side we can understand if its 0 or 1 based on the delay"
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for bit in binary_message:
            num_packets = self.random.randint(2, 6)
            for i in range(num_packets):
                packet = IP(dst="172.18.0.3")/TCP(dport=8000)
                self.send(packet)
            if(bit == '1'):
                self.sleep_random_time_ms(10,20)
            elif(bit == '0'):
                self.sleep_random_time_ms(20,50)
        
     
             
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        packets = []
        self.sniff(ilter=f"tcp and port 8000", stop_filter=process_packet)
        last_time = 0
        def process_packet(packet):
            current_time = packet.time
            difference = current_time - last_time
            if(0.02<difference < 0.05):
                "period between burst and its a 0"
                packets.append(0)
                last_time = current_time
            elif(0.01<difference<0.02):
                "period between burst and its a 1"
                packets.append(1)
                last_time = current_time
            else:
                last_time = current_time
        binary_message= ''.join(packets)
        packet_string = ''.join(self.convert_eight_bits_to_character(binary_message[packet]) for packet in packets)
        self.log_message(packet_string,log_file_name)
        
            
         



   