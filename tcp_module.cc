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

#include "Minet.h"
#include "tcpstate.h"

using namespace std;

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};


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
 	    MinetSendToMonitor(MinetMonitoringEvent("ip packet has arrived!"));
		
		//recieve a packet
		Packet pkt;
		MinetRecieve(mux, pkt);

		//get the header
		 pkt.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(pkt));
		 TCPHeader header = packet.FindHeader(Headers::TCPHeader);
		
		//get IP 
		IPHeader ip = pkt.FindHeader(Headers::IPHeader);
		
		//get IPs and Ports	
		Connection c;
		ip.GetDestIP(c.src);
		ip.GetSourceIP(c.dest);
		ip.GetProtocol(c.protocol);
		header.GetSourcePort(c.destport);
		header.GetDestPort(c.sourceport);

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
		

		if(connections = clist.end()){
		  MinetSendToMonitor(MinetMonitoringEvent("CONNECTION DOES NOT EXIST"));
		}

		
		//get the state
		unsigned int conn_state;
		conn_state = connections->state.GetState();
		
		switch(conn_state){
		 
		case LISTEN:{
			
		  //check if it is a syn
		  if(IS_SYN(flags)){
		   connections->state.SetState(SYN_RCVD); //change the status of the connection
		   connections->state.last_acked = connections.state.last_sent -1 ; //set the last ACK
		   connnections->state.SetLastRecvd(seq + 1);
		   
		   //send a packet-- needs to be done
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
		  connections->state.SetState(ESTABLISHED); //set state to established
		  connections->state.SetLastAcked(ack_num);
		  connections->state.SetSentRwnd(win_size);
		
		  //set up our sock
		  SockRequestResponse reply;
		  reply.type = write;
		  repl.connection = connections->connection;
		  repl.error = EOK;
		  repl.bytes = 0;
		  MinetSend(sock, reply);
		  
		  }
		break;
		}
		

		case SYN_SENT:{
		if(IS_ACK(flags) && IS_SYN(flags)){
		    
		  //update our connection state
		  connections->state.SetLastRecvd(seq+1);
		  
		 //create and send packet-- NEEDS TO BE DONE
		  
		
		  //set up our sock
		  SockRequestResponse reply;
		  reply.type = write;
                  repl.connection = connections->connection;
                  repl.error = EOK;
                  repl.bytes = 0;
                  MinetSend(sock, reply);
	
		
	           
		}
		}
		}
		


	    }

	    if (event.handle == sock) {
		// socket request or response has arrived 

		//modeled after udp_module.cc
		
		SockReqResponse req;
		MinetReceive(sock, req); //recieve the request

		//handling first connection
		switch(req.type){
		
		case CONNECT:
		{ 
		    /* not completed
		    *need to create and send syn packet */
 
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
