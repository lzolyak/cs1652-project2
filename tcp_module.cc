
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
void GeneratePacket(Packet &packet, TCPState st, unsigned char flags, Connection cc, unsigned bytes);

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
		printf("Can't connect to ip_mux");

		return -1;
	}

	if ( (sock == MINET_NOHANDLE) && 
			(MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

		MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
		printf("Can't accept from sock_module");

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
				printf("TCP/IP packet has arrived!\n");
				
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
					printf("CONNECTION DOES NOT EXIST");
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
							connections->state.SetLastRecvd(seq_num);
							connections->state.SetSendRwnd(win_size);
							
							Packet p;
							unsigned char f = 0;
							SET_SYN(f);
							SET_ACK(f);
							GeneratePacket(p, connections->state, f, c, 0);
							MinetSend(mux, p);
							usleep(10000);
							MinetSend(mux, p);
							connections->state.SetLastSent(connections->state.GetLastSent()+1);
							connections->state.SetState(SYN_RCVD);
							MinetSendToMonitor(MinetMonitoringEvent("SERVER: SYN recv. Sent SYN-ACK. Now in state SYN_RECV.\n"));
							printf("SERVER: SYN recv. Sent SYN-ACK. Now in state SYN_RECV.\n");
						}
						break;
					}

				case SYN_RCVD:{
						if(IS_ACK(flags)){
//#2a
// State:SYNC_RECV + Flag:ACK -> (no send) ESTABLISHED [server]
							connections->state.SetLastRecvd(seq_num);
							connections->state.SetLastAcked(ack_num+1); // this is an ack
							connections->state.SetSendRwnd(win_size);
							
							//set up our sock
							SockRequestResponse reply;
							reply.type = WRITE;
							reply.connection = connections->connection;
							reply.error = EOK;
							reply.bytes = 0;
							MinetSend(sock, reply);
							
							connections->state.SetState(ESTABLISHED);
							MinetSendToMonitor(MinetMonitoringEvent("SERVER: ACK to SYN recv. Send nothing. Now in state ESTABLISHED.\n"));							
							printf("SERVER: ACK to SYN recv. Send nothing. Now in state ESTABLISHED.\n");							
						}
						break;
					}
					

				case SYN_SENT:{
						if(IS_ACK(flags) && IS_SYN(flags)){
//#2a
// State:SYNC_SENT + Flag:SYN+ACK -> (Flag:ACK) State:ESTABLISHED [client]
							//update our connection state
							connections->state.SetLastRecvd(seq_num);
							connections->state.SetLastAcked(ack_num+1); // this is an ack
							connections->state.SetSendRwnd(win_size);	// still need to verify how rwnd vs "n" work
							
							//generate a ACK packet
							Packet p;
							unsigned char f = 0;
							SET_ACK(f);
							GeneratePacket(p, connections->state, f, c, 0);
							MinetSend(mux, p);				
							usleep(10000);
							MinetSend(mux, p);
							connections->state.SetLastSent(connections->state.GetLastSent()+1);
							connections->state.SetState(ESTABLISHED);
							
							//set up our sock
							SockRequestResponse reply;
							reply.type = WRITE;
							reply.connection = connections->connection;
							reply.error = EOK;
							reply.bytes = 0;
							MinetSend(sock, reply);
							
							MinetSendToMonitor(MinetMonitoringEvent("Client: SYN-ACK recv. Sent ACK. Now in state ESTABLISHED.\n"));
							printf("Client: SYN-ACK recv. Sent ACK. Now in state ESTABLISHED.\n");
							//todo: handle this ack not recv?
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
//enum srrType {CONNECT=0, ACCEPT=1, WRITE=2, FORWARD=3, CLOSE=4, STATUS=5};					
				case CONNECT:
					{ 
//#2a
// State:CLOSED + Req:CONNECT -> (Flag:SYN) State:SYN_SENT [client]
// have to create new connection
						TCPState tcps;
						tcps.SetState(SYN_SENT);
						tcps.SetLastAcked(rand()%32000); // notes say this should be random
						tcps.SetLastSent(rand()%32000);
						
						Connection c;
						//Connection(const IPAddress &s,
						//const IPAddress &d,
						//const unsigned short sport,
						//const unsigned short destport,
						//const unsigned char  proto);
						c = req.connection;
						c.srcport = 10000 + rand()%10000;
						
						tcps.SetLastSent(tcps.GetLastSent()+1); // about to send a packet
						ConnectionToStateMapping<TCPState> cs;
						cs.connection = c;
						cs.state = tcps;
						clist.push_front(cs);
						
						Packet p;
						unsigned char f = 0;
						SET_SYN(f);
						GeneratePacket(p, tcps, f, c, 0);
						MinetSend(mux, p);
						usleep(10000);
						MinetSend(mux, p);
						cs.state.SetLastSent(cs.state.GetLastSent()+1);


						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						// buffer is zero bytes
						repl.bytes=0;
						repl.error=EOK;
						MinetSend(sock,repl);

						MinetSendToMonitor(MinetMonitoringEvent("Client: SYN sent. Now in state SYN_SENT.\n"));
						printf("Client: SYN sent. Now in state SYN_SENT.\n");

						break;
					} 

				case ACCEPT:
					{ 
//#2a
// State:CLOSED + Req:ACCEPT -> (nothing) State:LISTEN [client]
// have to create new connection
						TCPState tcps;
						tcps.SetState(LISTEN);
						tcps.SetLastAcked(rand()); // notes say this should be random
						tcps.SetLastSent(tcps.GetLastAcked());
						
						Connection c;
						c = req.connection;
						
						ConnectionToStateMapping<TCPState> cs;
						cs.connection = c;
						cs.state = tcps;
						clist.push_front(cs);

						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.bytes=0;
						repl.error=EOK;
						MinetSend(sock,repl);
						MinetSendToMonitor(MinetMonitoringEvent("Server: Now in state LISTEN.\n"));
						printf("Server: Now in state LISTEN.\n");
						break;
					}
				case WRITE: {
					//TODO: check in state established.
					ConnectionList<TCPState>::iterator cst = clist.FindMatching(req.connection);
					
					Connection c = cst->connection;
					TCPState tcps = cst->state;
					
					const char payload[] = {'h', 'e', 'l', 'o', '\0'};
					Packet p(payload, 5);
					unsigned char f = 0;
					GeneratePacket(p, tcps, f, c, 5);
					MinetSend(mux, p);
					cst->state.SetLastSent(cst->state.GetLastSent()+1);
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

				case STATUS: {
					// nothing
					break;
					}

				default:
					break;

				}
			}
		}

		if (event.eventtype == MinetEvent::Timeout) {
		        
			//get the current time
			Time current_time;
			
                        for(ConnectionList<TCPState>::iterator clist_iterator = clist.begin(); clist_iterator!=clist.end(); clist_iterator++) {
				
			  if(current_time >= clist_iterator->timeout){ //check if we have a timeout
			     MinetSendToMonitor(MinetMonitoringEvent("timeout ! probably need to resend some packets"));
			     
			     //get the state
			     unsigned int timeout_state;
			     timeout_state = clist_iterator->state.GetState();
	
			     switch(timeout_state){
			        case SYN_SENT: {
				  if(clist_iterator.ExpireTimerTries()){ //check if we have exceeded our tries
					Buffer data;
				
				  	SockRequestResponse write(WRITE, data, 0, ECONN_FAILED);
					MinetSend(sock, write);
					clist_iterator->bTmrActive = false;
					clist_iterator->state.SetState(CLOSING);
					}
	
				  else{ //retransmit
					Packet new_syn;
					//Generate our packet
					
					//MinetSend(mux, new_syn);
					clist_iterator->timeout = current_time++;
				  }
				break;
				}
				
				case SYN_RCVD: {
				   if(clist_iterator.ExpireTimerTries()){ //check if we have exceeded our tries
	
					clist_iterator->bTmrActive = false;
					clist_iterator->state.SetState(LISTEN);
				   }
				   else{
					Packet new_syn_ack;
                                        //Generate our packet

                                        //MinetSend(mux, new_syn_ack);
                                        clist_iterator->timeout = current_time++;

				   }
				break;
				}

			     }
                          }
			}


		}

	}

	MinetDeinit();

	return 0;
}

//void GeneratePacket(Packet &packet, TCPState &st, unsigned char flags, Connection &cc) {
void GeneratePacket(Packet &packet, TCPState st, unsigned char flags, Connection cc, unsigned bytes) {
	//unsigned bytes = 0;
	Connection c = cc;
	TCPState s = st;
	// see: ip.h, line 71+
	IPHeader iph;
	//void SetProtocol(const unsigned char &proto);
	//void SetSourceIP(const IPAddress &addr);
	//void SetDestIP(const IPAddress &addr);
	//void SetChecksum();
		//noted as automatic in ip.h, after any set
	    iph.SetTotalLength(bytes+TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
		iph.SetProtocol(IP_PROTO_TCP);
		iph.SetSourceIP(c.src);
		iph.SetDestIP(c.dest);
	//cout<<iph<<"\n";
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
		//const unsigned TCP_HEADER_BASE_LENGTH=20;
		// but wireshark says it's setting to 16 and not 20, wtf
		//tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, packet);
		tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH+1, packet); // need 21, constant defined as 20
		tcph.SetSeqNum(s.GetLastAcked(), packet); // notice this is lastacked -- +1, since we're a new packet; ignore lost pockets, we're the next one no matter what
		tcph.SetAckNum(s.GetLastRecvd()+1, packet);	// notice acking last in
		tcph.SetFlags(flags, packet);
		tcph.SetWinSize(s.GetN(), packet); // difference between Rwnd and N?
		tcph.SetUrgentPtr(0, packet);
		//tcpstate.cc:   N = 16*TCP_MAXIMUM_SEGMENT_SIZE; //16 packets allowed in flight
		tcph.RecomputeChecksum(packet);
	cout<<tcph<<"\n";
	packet.PushBackHeader(tcph);
}
