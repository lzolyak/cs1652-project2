// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>
#include <deque>

#include "Minet.h"
#include "tcpstate.h"
#include "packet.h"
#include "ip.h"
#include "tcp.h"
#include "buffer.h"
#include "constate.h"

using namespace std;

/*
struct TCPState {
// need to write this?
	std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
	}
};
*/
// List of TCP states in diagram 18.12, p241 handbook. or, in tcpstate.h
//Email from Lange oct20: For the TCPState you can choose to use the one provided or come up with your own version. The recommended approach would be to make your own, using the provided one as an example. 
void GeneratePacket(Packet &packet, Connection connection, unsigned char flags);

int main(int argc, char * argv[]) {
	MinetHandle mux;
	MinetHandle sock;
	
	ConnectionList<TCPState> clist;

	MinetInit(MINET_TCP_MODULE);

	mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
	
	sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

	if ( (mux == MINET_NOHANDLE) && 
			(MinetIsModuleInConfig(MINET_IP_MUX)) ) {

		MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

		return -1;
	}

	if ( (sock == MINET_NOHANDLE) && 
			(MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

		MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

		return -1;
	}
	
	cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

	MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

	MinetEvent event;
	double timeout = 1;

	while (MinetGetNextEvent(event, timeout) == 0) {

		if ((event.eventtype == MinetEvent::Dataflow) && 
				(event.direction == MinetEvent::IN)) {
			
			if (event.handle == mux) {
				// ip packet has arrived!
				MinetSendToMonitor(MinetMonitoringEvent("TCP/IP packet has arrived!\n"));
				
				//recieve a packet
				Packet pkt;
				MinetReceive(mux, pkt);

				//get the header
				pkt.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(pkt));
				TCPHeader header = pkt.FindHeader(Headers::TCPHeader);
				
				//get IP 
				IPHeader ip = pkt.FindHeader(Headers::IPHeader);
				
				//get IPs and Ports	
				Connection c;
//struct Connection defined in sockint.h, line 32
				ip.GetDestIP(c.src);
				ip.GetSourceIP(c.dest);				// notice swap -- keep it in OUR perspective
				ip.GetProtocol(c.protocol);
				header.GetSourcePort(c.destport);	// ibid
				header.GetDestPort(c.srcport);

				//get the sequence number
				unsigned int seq_num;
				header.GetSeqNum(seq_num);

				//get the ack number
				unsigned int ack_num;
				header.GetAckNum(ack_num);

				//get the flags
				unsigned char flags;
				header.GetFlags(flags);

				//get the window size
				unsigned short win_size;
				header.GetWinSize(win_size);

				//get the urgency
				unsigned short urgent_ptr;
				header.GetUrgentPtr(urgent_ptr);

				
				//do something with the data of the packet eventually

				
				//check our connections
				ConnectionList<TCPState>::iterator connections = clist.FindMatching(c);
				

				if ( connections == clist.end() ){
					MinetSendToMonitor(MinetMonitoringEvent("CONNECTION DOES NOT EXIST"));
				}

				
				//get the state
				unsigned int conn_state;
				conn_state = connections->state.GetState();
				
				switch(conn_state){
				case CLOSED: {
					// nothing done
					break;
				}
				case LISTEN:{
//#2a
// State:SYNC_RECV + Flag:ACK -> (no send) ESTABLISHED [server]
						if(IS_SYN(flags)){
							connections->state.SetState(SYN_RCVD); //change the status of the connection
							connections->state.last_acked = connections->state.last_sent -1 ; //set the last ACK
							connections->state.SetLastRecvd(seq_num + 1);

							//generate a SYN, ACK packet
							Packet p;
							unsigned char f = 0;
							SET_SYN(f);
							SET_ACK(f);
							GeneratePacket(p, c, f);
							MinetSend(sock, p);
							break;							
						}
						else if(IS_FIN(flags)){
							//create a packet--needs to be done
							break;
						}
						break;
					}

				case SYN_RCVD:{
						if(IS_ACK(flags)){
//#2a
// State:SYNC_RECV + Flag:ACK -> (no send) ESTABLISHED [server]
							connections->state.SetState(ESTABLISHED); //set state to established
							connections->state.SetLastAcked(ack_num);
							connections->state.SetSendRwnd(win_size);
							
							//set up our sock
							SockRequestResponse reply;
							reply.type = WRITE;
							reply.connection = connections->connection;
							reply.error = EOK;
							reply.bytes = 0;
							MinetSend(sock, reply);
							
						}
						break;
					}
					

				case SYN_SENT:{
						if(IS_ACK(flags) && IS_SYN(flags)){
//#2a
// State:SYNC_SENT + Flag:SYN+ACK -> (Flag:ACK) State:ESTABLISHED [client]
							//update our connection state
							connections->state.SetLastRecvd(seq_num+1);

							//generate a ACK packet
							Packet p;
							unsigned char f = 0;
							SET_ACK(f);
							GeneratePacket(p, c, f);
							MinetSend(sock, p);				
							
							//set up our sock
							SockRequestResponse reply;
							reply.type = WRITE;
							reply.connection = connections->connection;
							reply.error = EOK;
							reply.bytes = 0;
							MinetSend(sock, reply);
							
							
							
						}
					}
				case ESTABLISHED: {
					// nothing done
					break;
					}
				case SEND_DATA: {
					// nothing done
					break;
					}
				case CLOSE_WAIT: {
					// nothing done
					break;
					}
				case FIN_WAIT1: {
					// nothing done
					break;
					}
				case CLOSING: {
					// nothing done
					break;
					}
				case LAST_ACK: {
					// nothing done
					break;
					}
				case FIN_WAIT2: {
					// nothing done
					break;
					}
				case TIME_WAIT: {
					// nothing done
					break;
					}
				}


				


			}

			if (event.handle == sock) {
				// socket request or response has arrived 

				//modeled after udp_module.cc
				
				SockRequestResponse req;
				MinetReceive(sock, req); //recieve the request

				//handling first connection
				switch(req.type){
					
				case CONNECT:
					{ 
//#2a
// State:CLOSED + Req:Connect -> (Flag:SYN) State:SYN_SENT [client]
// have to create new connection
						TCPState tcps;
						tcps.SetState(SYN_SENT);
						tcps.SetLastAcked(rand()); // notes say this should be random
						tcps.SetLastSent(tcps.GetLastAcked());
						
						Connection c;
						//Connection(const IPAddress &s,
						//const IPAddress &d,
						//const unsigned short sport,
						//const unsigned short destport,
						//const unsigned char  proto);
						c = req.connection;
						
						ConnectionToStateMapping<TCPState> cs;
						cs.connection = c;
						cs.state = tcps;
						clist.push_front(cs);
						
						Packet p;
						unsigned char f = 0;
						SET_SYN(f);
						GeneratePacket(p, c, f);
						MinetSend(sock, p);

						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						// buffer is zero bytes
						repl.bytes=0;
						repl.error=EOK;
						MinetSend(sock,repl);

						break;
					} 

				case ACCEPT:
					{ 
//#2a
/* not completed
*keep track of created connections */

						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.bytes=0;
						repl.error=EOK;
						MinetSend(sock,repl);
						break;
					}

				case CLOSE: //should work as is
					{
						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						// buffer is zero bytes
						repl.bytes=0;
						repl.error=ENOMATCH;
						MinetSend(sock,repl);
					}
					
					//will add other response types as needed

				default:
					break;

				}
			}
		}

		if (event.eventtype == MinetEvent::Timeout) {
			// timeout ! probably need to resend some packets
			
			MinetSendToMonitor(MinetMonitoringEvent("timeout ! probably need to resend some packets"));
		}

	}

	MinetDeinit();

	return 0;
}

void GeneratePacket(Packet &packet, Connection c, unsigned char flags) {
	// see: ip.h, line 71+
	IPHeader iph;
	//void SetProtocol(const unsigned char &proto);
	//void SetSourceIP(const IPAddress &addr);
	//void SetDestIP(const IPAddress &addr);
	//void SetChecksum();
		//noted as automatic in ip.h, after any set
		iph.SetProtocol(IP_PROTO_TCP);
		iph.SetSourceIP(c.src);
		iph.SetDestIP(c.dest);
	packet.PushFrontHeader(iph);
	
	// see: tcp.h, line 40+
	TCPHeader tcph;
	//void SetSourcePort(const unsigned short &port, const Packet &p);
	//void SetDestPort(const unsigned short &port, const Packet &p);
	//void SetSeqNum(const unsigned int &n, const Packet &p);
	//void SetAckNum(const unsigned int &n, const Packet &p);
	//void SetHeaderLen(const unsigned char &l, const Packet &p);
	//void SetFlags(const unsigned char &f, const Packet &p);
	//void SetWinSize(const unsigned short &w, const Packet &p);
	//void RecomputeChecksum(const Packet &p);
		tcph.SetSourcePort(c.srcport, packet);
		tcph.SetDestPort(c.destport, packet);
		tcph.SetSeqNum(0, packet);
		tcph.SetAckNum(0, packet);
		tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, packet);
		tcph.SetFlags(flags, packet);
		tcph.SetWinSize(0, packet);
		tcph.RecomputeChecksum(packet);
	packet.PushBackHeader(tcph);
}
