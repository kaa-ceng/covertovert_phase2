# Covert Timing Channel that exploits Idle Period Between Packet Bursts using TCP


Explain your study in detail as you share your work with the community in a public repository. Anyone should understand your project when read it without having a previous information about the homework.



## Project Description
This project implements a covert timing channel that exploits idle periods between packet bursts using TCP. The covert channel is designed to send binary messages by varying the timing between packet transmissions.

### Idle Period Between Packet Bursts
This technique encodes information by varying the duration of inactivity or idle time between bursts of packets. For example, a short idle period might represent a ‘0’, and a long idle period might represent a ‘1’. The sender controls the idle times between groups of packets and the receiver decodes the data by analyzing these gaps. 

The dot character is the stopping character for the covert channel communication. When the dot character is received, the entire covert channel communication finishes and the receiver stops capturing the new packets.

## Implementation
### send()
In this function, the sender encodes the binary message by varying the idle time between packet bursts. The parameters for the `send` function are defined in the `config.json` file.

#### Parameters
- `log_file_name`: The name of the log file where the binary message will be saved.
- `src_ip`: The source IP address for the packets.
- `dst_ip`: The destination IP address for the packets.
- `dst_port`: The destination port for the packets.
- `min_packets`: The minimum number of packets to send in each burst.
- `max_packets`: The maximum number of packets to send in each burst.
- `delay_0_min`: The minimum delay (in seconds) between bursts representing a '0' bit.
- `delay_1_min`: The minimum delay (in seconds) between bursts representing a '1' bit.

#### Process
1. **Generate Binary Message**: A binary message of length 128 bits is generated and logged to the specified log file.
2. **Start Timer**: The timer is started just before sending the first packet.
3. **Send Packets**: For each bit in the binary message:
   - A random number of packets (between `min_packets` and `max_packets`) is sent.
   - If the bit is '1', the sender waits for `delay_1_min` seconds before sending the next burst.
   - If the bit is '0', the sender waits for `delay_0_min` seconds before sending the next burst.
4. **End Timer**: The timer is stopped just after sending the last packet.
5. **Calculate Capacity**: The covert channel capacity is calculated as the number of bits (128) divided by the time taken to send the message, resulting in bits per second.
6. **Log Capacity**: The calculated covert channel capacity is printed to the console.

This method ensures that the binary message is encoded in the timing between packet bursts, allowing the receiver to decode the message by analyzing these intervals.


### receive()
In this function, the receiver decodes the transferred message by analyzing the time intervals between packet bursts. The parameters for the `receive` function are defined in the `config.json` file.

#### Parameters
- `log_file_name`: The name of the log file where the decoded message will be saved.
- `src_ip`: The source IP address for the packets.
- `dst_ip`: The destination IP address for the packets.
- `port`: The destination port for the packets.
- `threshold_0_min`: The minimum threshold (in seconds) for detecting a '0' bit.
- `threshold_0_max`: The maximum threshold (in seconds) for detecting a '0' bit.

#### Process
1. **Initialize Variables**: Initialize variables to store the packets, the last packet time and a flag to indicate when the dot character is received.
2. **Process Packets**: Use the `sniff` function from Scapy to capture packets and process each packet:
   - Calculate the time difference between the current packet and the last packet.
   - If the time difference is between `threshold_0_min` and `threshold_0_max`, append '0' to the packets list.
   - If the time difference is greater than `threshold_0_max`, append '1' to the packets list.
   - Update the last packet time.
   - Check if the length of the packets list is a multiple of 8, and convert the last 8 bits to a character.
   - If the character is a dot ('.'), set the flag to stop capturing packets.
3. **Stop Capturing**: Stop capturing packets when the dot character is received.
4. **Decode Message**: Join the packets list to form the binary message and convert it to the final message string.
5. **Log Message**: Save the decoded message to the specified log file.

This method ensures that the binary message is decoded by analyzing the timing between packet bursts, allowing the receiver to reconstruct the original message.


## Covert Channel Capacity
To measure the covert channel capacity, a binary message of length 128 bits (16 characters) was sent. The time taken to send the message was measured and the capacity was calculated as follows:

1. A binary message of length 128 bits created (contains 16 characters).
2. Start the timer just before sending the first packet.
3. Finish the timer just after sending the last packet.
4. Calculate the time difference in seconds.
5. Divide 128 by the calculated time in seconds to get the capacity in bits per second.

The covert channel capacity is approximately **1.28 bits per second**.

## Limitations
- The minimum delay for sending a '0' bit is set to `delay_0_min` (0.4 seconds).
- The minimum delay for sending a '1' bit is set to `delay_1_min` (0.8 seconds).
- The thresholds for detecting '0' and '1' bits on the receiver side are defined by `threshold_0_min` (0.4 seconds) and `threshold_0_max` (0.8 seconds).

We have set the minimum delay to 0.4 seconds because, based on our observations, network delays typically range from approximately 0.05 seconds to 0.35 seconds. If we set the delay below 0.35 seconds, a packet without any intentional delay could be mistaken for a packet with an idle time delay. This would make it difficult to distinguish between intentional delays and network delays, leading to incorrect decoding.

Setting the delay higher than 0.4 seconds would make the process less efficient, as it would take more time.

We set the second delay to 0.8 seconds because, as mentioned earlier, network delays range from approximately 0.05 seconds to 0.35 seconds. If we set the second delay to 0.5 seconds, for example, a packet with an idle delay of 0.4 seconds and a network delay of 0.3 seconds would arrive at the receiver at the same time as a packet with an idle delay of 0.5 seconds and a network delay of 0.2 seconds. This would create a conflict and result in incorrect message decoding.

We set the thresholds to 0.4 seconds and 0.8 seconds because our delays are 0.4 and 0.8 seconds, and network delays cannot exceed 0.4 seconds. This ensures that a packet with only network delay is not mistaken for a packet with an idle delay. Additionally, if the sender sends a packet with a 0.4-second delay, adding network delay to this cannot exceed 0.8 seconds. We can be confident that the time difference between the current packet arrival and the last packet arrival will be between 0.4 and 0.8 seconds for a packet with idle delay of 0.4 seconds.

Since the second delay is 0.8 seconds, any packet that arrives more than 0.8 seconds after the last packet has an idle delay of 0.8 seconds for sure and is encoded with a bit "1".

## Usage
To run the sender and receiver, use the following commands:

# Start the receiver
make receive

# Start the sender
make send