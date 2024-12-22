import time
from scapy.all import IP, TCP, send, sniff
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    def send(self, receiver_ip, receiver_port, sender_port, short_delay, long_delay, message_length, log_file):
        """
        Send a covert message using timing delays between packet bursts.

        Parameters:
        receiver_ip: The IP address of the receiver.
        receiver_port: The port the receiver listens on.
        sender_port: The port the sender sends from.
        short_delay: Delay (in seconds) representing binary '0'.
        long_delay: Delay (in seconds) representing binary '1'.
        message_length: Length of the binary message to send.
        log_file: Path to log the sent message.
        """
        # Generate a random binary message
        message = ''.join(self.get_random_message(message_length))

        # Log the generated message
        with open(log_file, "w") as log:
            log.write(message)

        print(f"Sending message: {message}")

        # Send packets with appropriate delays
        for bit in message:
            pkt = IP(dst=receiver_ip) / TCP(dport=receiver_port, sport=sender_port)
            send(pkt, verbose=False)
            # Delay based on the bit value
            time.sleep(short_delay if bit == '0' else long_delay)

        # Send a termination packet (optional, for synchronization)
        send(IP(dst=receiver_ip) / TCP(dport=receiver_port, sport=sender_port, flags="F"), verbose=False)
        print("Message sent!")

    def receive(self, sender_ip, sender_port, receiver_ip, receiver_port, short_delay, long_delay, log_file):
        """
        Receive a covert message by decoding timing delays between packet bursts.

        Parameters:
        sender_ip: The IP address of the sender.
        sender_port: The port the sender sends from.
        receiver_ip: The IP address of the receiver.
        receiver_port: The port the receiver listens on.
        short_delay: Threshold for '0'.
        long_delay: Threshold for '1'.
        log_file: Path to log the received message.
        """
        print("Listening for packets...")
        message = []
        previous_time = None

        def packet_handler(pkt):
            nonlocal previous_time
            current_time = time.time()

            if previous_time is not None:
                # Calculate time difference between consecutive packets
                idle_time = current_time - previous_time
                # Decode the bit based on idle_time
                if idle_time < (short_delay + long_delay) / 2:
                    message.append('0')
                else:
                    message.append('1')

            previous_time = current_time

        # Sniff packets with filter for sender/receiver communication
        sniff(filter=f"tcp and host {sender_ip} and port {sender_port}",
              prn=packet_handler, timeout=30)

        # Log the received message
        decoded_message = ''.join(message)
        with open(log_file, "w") as log:
            log.write(decoded_message)

        print(f"Received message: {decoded_message}")
