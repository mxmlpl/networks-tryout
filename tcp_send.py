#!/usr/bin/env python3
"""
tcp_send.py
==============================================================
A simple TCP packet sender using Scapy.
Demonstrates how to manually craft and send TCP packets
at the raw socket level — useful for learning networking basics.

WHAT THIS SCRIPT DOES
--------------------------------------------------------------
1. Crafts an IP packet with a destination address
2. Adds a TCP layer on top (SYN, ACK, or custom flags)
3. Sends the packet and optionally waits for a response
4. Prints a summary of what was sent and received

HOW TO RUN
--------------------------------------------------------------
1. Install Scapy:
       pip install scapy

2. Run with sudo/root (raw sockets require root privileges):
       sudo python3 tcp_send.py

   Or on Windows (run terminal as Administrator):
       python tcp_send.py

REQUIREMENTS
--------------------------------------------------------------
- Python 3.x
- Scapy  (pip install scapy)
- Root / Administrator privileges

EDUCATIONAL CONCEPTS COVERED
--------------------------------------------------------------
- IP layer (Layer 3)
- TCP layer (Layer 4)
- TCP flags: SYN, ACK, FIN, RST
- TCP 3-way handshake (SYN → SYN-ACK → ACK)
- Raw socket communication
"""

from scapy.all import (
    IP,       # Internet Protocol layer (Layer 3)
    TCP,      # Transmission Control Protocol layer (Layer 4)
    sr1,      # Send one packet and receive one reply
    send,     # Send a packet without waiting for a reply
    conf      # Scapy configuration
)

import random  # used to generate a random source port

# ==============================================================
# CONFIGURATION  –  change these to your needs
# ==============================================================

# The target IP address to send the packet to
# Replace with your target (e.g. a local VM or test server)
TARGET_IP   = "93.184.216.34"   # example.com

# The target port to connect to
TARGET_PORT = 80                 # HTTP port

# Your source port (random is realistic and avoids conflicts)
SOURCE_PORT = random.randint(1024, 65535)

# Timeout in seconds to wait for a response
TIMEOUT     = 2

# ==============================================================
# TCP FLAGS EXPLAINED
# ==============================================================
# Scapy uses a string or integer to set TCP flags.
# Common flags:
#   "S"  = SYN   – start a connection (used in step 1 of handshake)
#   "A"  = ACK   – acknowledge received data
#   "SA" = SYN-ACK – server's response to SYN
#   "FA" = FIN-ACK – gracefully close connection
#   "R"  = RST   – reset / forcefully close connection
#   "P"  = PSH   – push data immediately to the application
# ==============================================================


def send_syn():
    """
    send_syn()
    ----------------------------------------------------------
    Sends a TCP SYN packet to the target.
    This is Step 1 of the TCP 3-way handshake.

    SYN packet = "Hey, I want to connect to you!"

    The server should respond with SYN-ACK if the port is open,
    or RST if the port is closed.
    """
    print("\n" + "="*55)
    print("  STEP 1: Sending TCP SYN packet")
    print("="*55)
    print(f"  Target  : {TARGET_IP}:{TARGET_PORT}")
    print(f"  Source  : (your IP):{SOURCE_PORT}")
    print(f"  Flag    : SYN")
    print("="*55 + "\n")

    # ── Build the packet ──────────────────────────────────────

    # Layer 3: IP header
    # dst = destination IP address
    ip_layer = IP(dst=TARGET_IP)

    # Layer 4: TCP header
    # dport = destination port
    # sport = source port
    # flags = "S" means SYN
    # seq   = initial sequence number (random for realism)
    tcp_layer = TCP(
        dport = TARGET_PORT,
        sport = SOURCE_PORT,
        flags = "S",
        seq   = random.randint(1000, 9000)
    )

    # Stack the layers using the / operator (Scapy's syntax)
    # IP / TCP = a complete packet
    packet = ip_layer / tcp_layer

    # ── Send and wait for a response ─────────────────────────
    # sr1() = Send 1 packet, Receive 1 response
    # timeout = how long to wait for a reply (seconds)
    # verbose = 0 suppresses Scapy's default output
    response = sr1(packet, timeout=TIMEOUT, verbose=0)

    # ── Analyse the response ──────────────────────────────────
    if response is None:
        print("  [!] No response received (port may be filtered by firewall)")

    elif response.haslayer(TCP):
        tcp_resp = response[TCP]

        if tcp_resp.flags == "SA":   # SYN-ACK
            print("  [+] Received SYN-ACK → Port is OPEN!")
            print(f"      Server seq : {tcp_resp.seq}")
            print(f"      Server ack : {tcp_resp.ack}")
            print("\n  The server wants to complete the handshake.")
            print("  Sending RST to close cleanly without completing it...\n")

            # Send RST to close the half-open connection politely
            # (otherwise the server keeps waiting)
            send_rst(tcp_resp.seq + 1)

        elif tcp_resp.flags == "R" or tcp_resp.flags == "RA":  # RST
            print("  [-] Received RST → Port is CLOSED")

        else:
            print(f"  [?] Received unexpected TCP flags: {tcp_resp.flags}")

    else:
        print("  [?] Received a non-TCP response:")
        response.summary()


def send_rst(ack_num):
    """
    send_rst(ack_num)
    ----------------------------------------------------------
    Sends a TCP RST (reset) packet to close a half-open
    connection after we received a SYN-ACK.

    RST = "Never mind, abort the connection."

    @param ack_num  The acknowledgement number from the SYN-ACK
    """
    ip_layer  = IP(dst=TARGET_IP)
    tcp_layer = TCP(
        dport = TARGET_PORT,
        sport = SOURCE_PORT,
        flags = "R",      # RST flag
        seq   = ack_num   # our next sequence number
    )

    send(ip_layer / tcp_layer, verbose=0)
    print("  [+] RST sent – connection closed cleanly.")


def send_custom_packet(flags="S", payload=""):
    """
    send_custom_packet(flags, payload)
    ----------------------------------------------------------
    Sends a TCP packet with custom flags and an optional
    payload (application data).

    Examples:
        send_custom_packet("S")          – SYN
        send_custom_packet("A")          – ACK
        send_custom_packet("PA", "GET / HTTP/1.0\\r\\n\\r\\n")  – HTTP request

    @param flags    TCP flag string  e.g. "S", "A", "PA", "FA"
    @param payload  Optional string payload (application data)
    """
    print("\n" + "="*55)
    print(f"  Sending custom TCP packet  [flags={flags}]")
    print("="*55)

    ip_layer  = IP(dst=TARGET_IP)
    tcp_layer = TCP(
        dport = TARGET_PORT,
        sport = SOURCE_PORT,
        flags = flags
    )

    # Build packet with or without payload
    if payload:
        # The / operator also works with raw string payloads
        packet = ip_layer / tcp_layer / payload
        print(f"  Payload : {repr(payload)}")
    else:
        packet = ip_layer / tcp_layer

    # Show a Scapy summary of the packet before sending
    print("\n  Packet summary:")
    packet.show()

    response = sr1(packet, timeout=TIMEOUT, verbose=0)

    if response:
        print("\n  Response received:")
        response.show()
    else:
        print("\n  [!] No response received.")


def print_tcp_handshake_explanation():
    """
    print_tcp_handshake_explanation()
    ----------------------------------------------------------
    Prints a simple ASCII diagram of the TCP 3-way handshake
    for educational purposes.
    """
    print("""
  TCP 3-WAY HANDSHAKE
  ══════════════════════════════════════════════════
   Client                          Server
     │                               │
     │  ──── SYN ──────────────────► │   Step 1: Client says "Hello"
     │                               │
     │  ◄─── SYN-ACK ─────────────── │   Step 2: Server says "Hello back"
     │                               │
     │  ──── ACK ──────────────────► │   Step 3: Client confirms
     │                               │
     │  ════ Connection established ═ │
     │                               │
     │  ──── Data ─────────────────► │   Now data can flow both ways
     │  ◄─── Data ─────────────────── │
     │                               │
  ══════════════════════════════════════════════════
  SYN     = Synchronise (start connection)
  ACK     = Acknowledge (confirm receipt)
  SYN-ACK = Both flags set (server's response)
    """)


# ==============================================================
# MAIN  –  runs when the script is executed directly
# ==============================================================

if __name__ == "__main__":

    print("""
  ╔══════════════════════════════════════════════════════╗
  ║           TCP Packet Sender  –  via Scapy            ║
  ║         Networking Basics / Educational Tool         ║
  ╚══════════════════════════════════════════════════════╝
    """)

    # Print the educational handshake diagram first
    print_tcp_handshake_explanation()

    # Send a SYN packet and analyse the response
    # This demonstrates Step 1 of the TCP 3-way handshake
    send_syn()

    print("\n" + "="*55)
    print("  Done! Try modifying TARGET_IP and TARGET_PORT")
    print("  at the top of this file to test other hosts.")
    print("="*55 + "\n")
