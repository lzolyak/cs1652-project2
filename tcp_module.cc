
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
	
	MinetEvent event;
	double timeout = 1;

	while (MinetGetNextEvent(event) == 0) { // , timeout

		cout<<"!!! Event type direction: "<<event.eventtype<<" "<<event.direction<<"\n";

		if ((event.eventtype == MinetEvent::Dataflow) || 
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

				unsigned short totallength = 0;
				ip.GetTotalLength(totallength);
				unsigned char IPhlength = 0;
				ip.GetHeaderLength(IPhlength);
				IPhlength *= 4;
				unsigned char TCPhlength = 0;
				header.GetHeaderLen(TCPhlength);
				TCPhlength *= 4;
				unsigned datalength = totallength - IPhlength - TCPhlength;

				Buffer bufraw = pkt.GetPayload();
				Buffer buf = bufraw.ExtractFront(datalength);
				
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
							usleep(10000); // repeat because ARP isn't populated yet
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
							connections->state.SetLastAcked(ack_num); // this is an ack
							connections->state.SetSendRwnd(win_size);
							
							connections->state.SetState(ESTABLISHED);

							//set up our sock
							SockRequestResponse reply;
							reply.type = WRITE;
							reply.connection = connections->connection;
							reply.error = EOK;
							reply.bytes = 0;
							MinetSend(sock, reply);
							
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
							connections->state.SetLastAcked(ack_num+1);	// this is an ack -- notice +1
									// previously had ack_num+1. should not be necessary
							connections->state.SetSendRwnd(win_size);	// still need to verify how rwnd vs "n" work
							
							//generate a ACK packet
							Packet p;
							unsigned char f = 0;
							SET_ACK(f);
							GeneratePacket(p, connections->state, f, c, 0);
							MinetSend(mux, p);				
							//connections->state.SetLastSent(connections->state.GetLastSent()+1);
							//ack shouldn't increment
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

// temporarily send some data from a rigid 
							const char payload[] = {'h', 'e', 'l', 'o', '\0'};
							{
							Packet q(payload, 5);
							unsigned char g = 0;
							SET_ACK(g);
							SET_PSH(g);
							GeneratePacket(q, connections->state, g, c, 5);
							MinetSend(mux, q);
							connections->state.SetLastSent(connections->state.GetLastSent()+5);
							}


						}
					}
				case ESTABLISHED: {
						if (IS_ACK(flags)) {
							printf("\tA packet was acknowledged: %d\n", ack_num);
							connections->state.SetLastAcked(ack_num+1); // it subtracts one!
							printf("\tGetLastAcked: %d\n", connections->state.GetLastAcked());
							


						}

						if (IS_FIN(flags)) {
							printf("\tFIN packet.\n");
							// RECV: fin, SEND ack -> CLOSE_WAIT
						}
						
						if ( buf.GetSize() > 0 )
						{
							printf("\tData packet data size: %d\n", buf.GetSize());
							connections->state.SetLastRecvd(seq_num + buf.GetSize() - 1); // notice this is ack number
							// OR data
							// send ack!
							Packet p;
							unsigned char f = 0;
							SET_ACK(f);
							GeneratePacket(p, connections->state, f, c, 0);
							MinetSend(mux, p);				
							// connections->state.SetLastSent(connections->state.GetLastSent()+1);
							// an ack shouldn't increment the sent

							// push data to socket
							/* SockRequestResponse reply;
							reply.type = WRITE;
							reply.connection = c;
							reply.error = EOK;
							reply.bytes = buf.GetSize();
							reply.data = buf;
							*/
							  SockRequestResponse write(WRITE,
										    c,
										    buf,
										    buf.GetSize(),
										    EOK);
							MinetSend(sock, write);
							printf("\t\tData should have been given back to socket.|");
							cout<<buf;
							printf("|\n");
						}
						break;
					}
				case SEND_DATA: {
					// NOT covered in the state diagram
					break;
					}
				case CLOSE_WAIT: {
					// send a fin, transition to LAST_ACK
					break;
					}
				case FIN_WAIT1: {
					// RECV ack SEND nothing -> FIN_WAIT_2
					// RECV fin SEND ack -> CLOSING
					// RECV fin,ack SEND ack -> time_wait (=die for this project)
					break;
					}
				case CLOSING: {
					// RECV ack -> TIME_WAIT
					// nothing done
					break;
					}
				case LAST_ACK: {
					// die.
					break;
					}
				case FIN_WAIT2: {
					// RECV fin SEND ack -> TIME_WAIT (=die)
					break;
					}
				case TIME_WAIT: {
					// for this project, just die
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
						usleep(10000); // do this because arp isn't populated yet
						MinetSend(mux, p);
						cs.state.SetLastSent(cs.state.GetLastSent()+1);


						SockRequestResponse reply;
						reply.type=STATUS;
						reply.connection=req.connection;
						// buffer is zero bytes
						reply.bytes=0;
						reply.error=EOK;
						MinetSend(sock, reply);

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
						tcps.SetLastAcked(rand()%32000); // notes say this should be random
						tcps.SetLastSent(tcps.GetLastAcked());
						
						Connection c;
						c = req.connection;
						
						ConnectionToStateMapping<TCPState> cs;
						cs.connection = c;
						cs.state = tcps;
						clist.push_back(cs);

						SockRequestResponse reply;
						reply.type=STATUS;
						reply.connection=req.connection;
						reply.bytes=0;
						reply.error=EOK;
						MinetSend(sock, reply);
						MinetSendToMonitor(MinetMonitoringEvent("Server: Now in state LISTEN.\n"));
						printf("Server: Now in state LISTEN.\n");
						break;
					}
				case WRITE: {

					//TRY THIS 
					ConnectionList<TCPState>::iterator cst = clist.FindMatching(req.connection);

					if(cst == clist.end()){
					SockRequestResponse reply;
					reply.type = STATUS;
					reply.connection = req.connection;
					reply.bytes = 0;
					reply.error = ENOMATCH;
					MinetSend(sock, reply);
					}
		
					else{
				
					cout<<"Are we here yet?\n";
					//TODO: Set "psh" flag?
					//TODO: seq# should be last acked...
					//TODO: check in state established.
					
					Connection c = cst->connection;
					TCPState tcps = cst->state;
					Buffer buf = req.data;
					unsigned int datasize = buf.GetSize();
					datasize = min(TCP_MAXIMUM_SEGMENT_SIZE, datasize);
					
// begin print incoming data to console
					printf("DATA|");
					//http://stackoverflow.com/questions/8170697/printf-a-buffer-of-char-passing-the-length-in-c
					char printt[2];
					printt[1] = '\0';
					unsigned int i;
					for (i = 0; i < datasize; ++i) {
						buf.GetData(printt, (size_t)1, i);
						printf(printt);
					}
					printf("|ENDDATA");
// end print incoming data to console
					
					//const char payload[] = {'h', 'e', 'l', 'o', '\0'};
					//Packet p(payload, 5);
					Packet p(buf.ExtractFront(datasize));
							// should I really extract it, or keep it there and move?
							// how the hell can i handle packet history for resends?
							// maybe i should just save actual "last packet sent"...
							// ...the whole damned packet?
					unsigned char f = 0;
					SET_ACK(f);
					SET_PSH(f);
					GeneratePacket(p, tcps, f, c, datasize);
					MinetSend(mux, p);
// TODO: wait for ack... send more if more
					cst->state.SetLastSent(cst->state.GetLastSent()+buf.GetSize());
					}
					break;
					}
				

				case CLOSE: //should work as is
					{
						// application requests close -> SEND fin -> FIN_WAIT_1
						//   that isn't a packet from mux...
						SockRequestResponse reply;
						reply.type=STATUS;
						reply.connection=req.connection;
						// buffer is zero bytes
						reply.bytes=0;
						reply.error=ENOMATCH;
						MinetSend(sock, reply);
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
			// timeout ! probably need to resend some packets
			
			MinetSendToMonitor(MinetMonitoringEvent("timeout ! probably need to resend some packets"));
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
		printf("\tSeq#: XXX\n\tLastAck#: %d\n", s.GetLastAcked());
		tcph.SetAckNum(s.GetLastRecvd()+1, packet);	// notice acking last in
		tcph.SetFlags(flags, packet);
		tcph.SetUrgentPtr(0, packet);
		//tcpstate.cc:   N = 16*TCP_MAXIMUM_SEGMENT_SIZE; //16 packets allowed in flight
		//tcph.SetWinSize(s.GetN(), packet); // difference between Rwnd and N?
		// for this project: implement as stop-and-wait, one packet only
		//tcph.SetWinSize(s.GetRwnd(), packet);
		tcph.SetWinSize(4096, packet);
		tcph.RecomputeChecksum(packet);
	//cout<<tcph<<"\n";
	packet.PushBackHeader(tcph);
}
