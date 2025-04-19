"""
A simple virtual IP load balancing switch (a switch that will map, in round-robin fashion, a virtual IP address to a set of real IP addresses associated with servers “behind” it) to be used in a POX SDN framework

Made by Banana Throwing Machine, Mar 23, 2025
"""

from pox.core import core                     
import pox.openflow.libopenflow_01 as of      
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp  

class LoadBalancer(object):
    """
    The virtual IP load balancing switch class
    """

    def __init__(self):
        """
        Class constructor, with hard-coded serverIPs, serverMACs and virtualIP
        """
        self.virtualIP = IPAddr("10.0.0.10")
        self.clientIPs = []
        self.clientMACs = []
        self.serverIPs = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
        self.serverMACs = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]
        self.flowTable = None
        self.nextServerIndex = 0
        core.openflow.addListeners(self)

    def _handle_PacketIn(self, event):
        """
        Handles all incoming packets, which would be packets sent to the switch there is no switch rule for 
        """
        packet = event.parsed.next
        if event.parsed.type == ethernet.ARP_TYPE and packet.opcode == arp.REQUEST: # Only do something if the packet is a ARP request

            if packet.protodst == self.virtualIP: # For ARP requests coming from clients to the virtual IP
                sourceIP = self.virtualIP
                sourceMAC = self.serverMACs[self.nextServerIndex]
                if packet.protosrc not in self.clientIPs: # Only adds client info, flow rules, and moves the index on new client connections
                    self.clientIPs.append(packet.protosrc)
                    self.clientMACs.append(packet.hwsrc)
                    msg = of.ofp_flow_mod(match=of.ofp_match(dl_type=0x0800, nw_proto=1, in_port=event.port, nw_dst=self.virtualIP))
                    msg.actions.append(of.ofp_action_nw_addr.set_dst(self.serverIPs[self.nextServerIndex]))
                    msg.actions.append(of.ofp_action_output(port=self.nextServerIndex + 5))
                    self.flowTable.send(msg) 
                    # Added new flow rule:
                    # For all ipv4 ICMP traffic coming from the arp requester's port and headed to the controller's virtual IP
                    # Change the destination IP to the next server's IP and send the traffic to that server's port
                    self.nextServerIndex = (self.nextServerIndex + 1) % len(self.serverMACs)
            
            elif packet.protodst in self.clientIPs: # For ARP requests coming from servers to listed clients
                clientIndex = self.clientIPs.index(packet.protodst)
                sourceIP = packet.protodst
                sourceMAC = self.clientMACs[clientIndex]
                msg = of.ofp_flow_mod(match=of.ofp_match(dl_type=0x0800, nw_proto=1, in_port=event.port, nw_src=packet.protosrc, nw_dst=packet.protodst))       
                msg.actions.append(of.ofp_action_nw_addr.set_src(self.virtualIP))
                msg.actions.append(of.ofp_action_output(port=clientIndex + 1))
                self.flowTable.send(msg)
                # Added new flow rule:
                # For all ipv4 ICMP traffic coming from the arp requester's port and IP and headed to the requester's destination
                # Change the source IP to the controller's virtual IP and send the traffic to the port for the requester's destination
            
            else: # Incase a random ARP request (one not going to the virtual IP or any client IP) gets sent to the switch
                return
            
            # After the switches are sent and the sourceMAC and sourceIP determined above, the ARP reply is built and sent
            arpReply = arp()
            arpReply.opcode = arp.REPLY     
            arpReply.hwsrc = sourceMAC
            arpReply.hwdst = packet.hwsrc
            arpReply.protosrc = sourceIP
            arpReply.protodst = packet.protosrc
            # Creates the ARP reply
            ether = ethernet()
            ether.src = sourceMAC
            ether.dst = packet.hwsrc
            ether.type = ethernet.ARP_TYPE
            ether.payload = arpReply
            # Creates the ethernet packet
            msg = of.ofp_packet_out(in_port = of.OFPP_NONE)
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.flowTable.send(msg)
            # Sends the ethernet packet to the port the request came from

    def _handle_ConnectionUp(self, event):
        """
        Handles a switch connecting to this controller by recording it a global variable and deleting all of it's previous flow rules
        """
        self.flowTable = event.connection
        self.flowTable.send(of.ofp_flow_mod(command=of.OFPFC_DELETE)) # Deletes all rules currently on the table

def launch():
    """
    Launch method to allow POX to create a LoadBalancer object within it's framework
    """
    core.registerNew(LoadBalancer)