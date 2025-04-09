#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/nstime.h"
#include "ns3/netanim-module.h"

#include <iostream>
#include <fstream>
#include <string>

#define MAX_SIMULATION_TIME 10.0
/*
CODE REFERENCES:
https://phdprime.com/how-to-simulate-edge-computing-projects-using-ns3/

https://ns3simulation.com/how-to-implement-end-to-end-encryption-in-ns3/#:~:text=To%20implement%20end-to-end,encryption%20and%20decryption%20of%20data

https://ns3simulation.com/how-to-implement-edge-computing-security-in-ns3/
*/
using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("EdgeCompNorm");

/*------------------------------------||| CLASSES FOR CLIENT AND EDGE NODES |||--------------------------------------------------------------*/
//Client application for each client node
class ClientApp : public Application{
	public:
		ClientApp(){}
		virtual ~ClientApp(){}
		//Setup client node
		void Setup(Address address, uint16_t port, std::string message, Address nextAddr)
		{	m_myAddress = address; m_peerPort = port; m_message = message; m_sendAddress = nextAddr;	}
	private:
		virtual void StartApplication(){
			if(!m_socket) m_socket = Socket::CreateSocket(GetNode(), 
						  TypeId::LookupByName("ns3::UdpSocketFactory"));
			m_socket->Bind(m_myAddress); //Bind client address to socket
			Simulator::Schedule(Simulator::Now(), &ClientApp::SendPacket, this);
			m_socket->SetRecvCallback(MakeCallback(&ClientApp::ReceivePacket, this));
		}
		virtual void StopApplication(){
			if (m_socket) {m_socket->Close(); m_socket=NULL;} NS_LOG_INFO("Socket Dereference Successful");
		}
		void SendPacket(){
			Ptr<Packet> packet = Create<Packet>((uint8_t*)m_message.c_str(), m_message.size());
			if(m_socket){
				m_socket->SendTo(packet, 0, m_sendAddress);
				std::cout << "At time " << Simulator::Now() << ", " << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4()
				<< " sent msg to " << InetSocketAddress::ConvertFrom(m_sendAddress).GetIpv4()  << std::endl;
				Simulator::Schedule(Simulator::Now(), &ClientApp::SendPacket, this);
			}
		}
		void ReceivePacket(Ptr<Socket> socket){
			Address from; //Receive returned message from edge server
			Ptr<Packet> packet = socket->RecvFrom(from);
			std::cout << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4() << " received msg from " 
			<< InetSocketAddress::ConvertFrom(from).GetIpv4() << " at " << Simulator::Now() << std::endl;
			uint8_t buffer[1024];
			packet->CopyData(buffer, packet->GetSize());
			std::string receivedMsg((char*)buffer, packet->GetSize());
			std::cout << "Received msg: " << receivedMsg << std::endl << std::endl;
		}
		Ptr<Socket> m_socket; Address m_myAddress, m_sendAddress;
		uint16_t m_peerPort; std::string m_message;
};

//Edge application for chosen edge server node as sink
class EdgeApp : public Application {
	public:
		EdgeApp() {}
		virtual ~EdgeApp() {}
		//Setup edge node
		void Setup(Address address, uint16_t port)
		{	m_myAddress = address; m_peerPort = port; 	}
	private:
		virtual void StartApplication() {
			if(!m_socket) m_socket = Socket::CreateSocket(GetNode(), 
						  TypeId::LookupByName("ns3::UdpSocketFactory"));
			m_socket->Bind(m_myAddress); //Bind edge server address to socket
			m_socket->SetRecvCallback(MakeCallback(&EdgeApp::ReceivePacket, this));
		}
		virtual void StopApplication() {
			if (m_socket) {m_socket->Close(); m_socket=NULL;} NS_LOG_INFO("Socket Dereference Successful");
		}
		void ReceivePacket(Ptr<Socket> socket) {
			Address from; // Receive a message from client
			Ptr<Packet> packet = socket->RecvFrom(from);
			std::cout << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4() << " received msg from " 
			<< InetSocketAddress::ConvertFrom(from).GetIpv4() << " at " << Simulator::Now() << std::endl;
			uint8_t buffer[1024];
			packet->CopyData(buffer, packet->GetSize());
			std::string receivedMsg((char*)buffer, packet->GetSize());
			std::cout << "Received msg: " << receivedMsg << std::endl;
			// Return a message to corresponding client
			std::stringstream returnMsg;
			returnMsg << "This is a return msg from " << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4() 
				     << " to " << InetSocketAddress::ConvertFrom(from).GetIpv4();
			std::string strReturnMsg = returnMsg.str();
			Ptr<Packet> returnPacket = Create<Packet>((uint8_t*)strReturnMsg.c_str(), strReturnMsg.size());
			if(m_socket){
				m_socket->SendTo(returnPacket, 0, from);
				std::cout << "At time " << Simulator::Now() << ", " << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4()
				<< " sent msg to " << InetSocketAddress::ConvertFrom(from).GetIpv4() << std::endl << std::endl;
			}
		}
		Ptr<Socket> m_socket; Address m_myAddress; uint16_t m_peerPort; 
};

/*------------------------------------||| MAIN FUNCTION TO EXECUTE ALL CODE |||--------------------------------------------------------------*/
int main(int argc, char *argv[]){
	//Set simulation timeframe (in seconds)
	double simTime = 10.0;
	uint32_t numClients = 10, numEdgeServers = 3; //10 devices/clients, 3 edge servers
	CommandLine cmd;
	cmd.AddValue("simTime", "Simulation time", simTime);
  	cmd.AddValue("numClients", "Number of client nodes", numClients);
  	cmd.AddValue("numEdgeServers", "Number of edge server nodes", numEdgeServers);
	cmd.Parse(argc, argv);
	
	Time::SetResolution(Time::NS);
    	LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    	LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    	
	//Create client, edge, and cloud nodes
	NodeContainer clients, edgeNodes, cloudNodes;
	clients.Create(numClients);        //10 client devices
	edgeNodes.Create(numEdgeServers);  //3 edge servers
	cloudNodes.Create(1); 		    //1 cloud server
	
	///Set up Point-to-Point links
	PointToPointHelper pp1;
	pp1.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
	pp1.SetChannelAttribute("Delay", StringValue("2ms"));
	
	//Install Internet stack
	InternetStackHelper internet;
	internet.Install(clients); internet.Install(edgeNodes); internet.Install(cloudNodes);
	
	//Connect nodes and assign IPv4 addresses to the nodes
	Ipv4InterfaceContainer edgeInterfaces, cloudInterfaces;
	Ipv4AddressHelper ipv4;
	ipv4.SetBase("10.1.1.0", "255.255.255.0"); //Starting IP: 10.1.1.1
	//Client to Edge connections
	for (uint32_t i = 0; i < numClients; ++i){
		NetDeviceContainer devices = pp1.Install(clients.Get(i), edgeNodes.Get(i % numEdgeServers));
		edgeInterfaces.Add(ipv4.Assign(devices));
		ipv4.NewNetwork();
	}
	//Include a connection between edge server nodes 1 and 2
	edgeInterfaces.Add(ipv4.Assign(pp1.Install(edgeNodes.Get(1), edgeNodes.Get(2))));
	ipv4.NewNetwork();
	//Edge to Cloud connections
	for (uint32_t i = 0; i < numEdgeServers; ++i){
		NetDeviceContainer cloudLinks = pp1.Install(edgeNodes.Get(i), cloudNodes.Get(0));
		cloudInterfaces.Add(ipv4.Assign(cloudLinks));
		ipv4.NewNetwork();
	}
	
	//Set up sockets for custom packets to travel
	uint16_t port = 8080; Address edgeAddress;
	for (uint32_t k = 0; k<numClients; ++k){
		std::stringstream msg;
		msg << "This is a normal msg from client node " << k+1;
        	if(!k) edgeAddress = InetSocketAddress(cloudInterfaces.GetAddress(4), port);
        	else edgeAddress = InetSocketAddress(cloudInterfaces.GetAddress(2), port);
        	
        	Ptr<ClientApp> clientApps = CreateObject<ClientApp>();
		clientApps->Setup(InetSocketAddress(edgeInterfaces.GetAddress(2*k), port), port, msg.str(),
				edgeAddress);
		clients.Get(k)->AddApplication(clientApps);
		clientApps->SetStartTime(Seconds(1.0));
		clientApps->SetStopTime(Seconds(simTime));
	}
	
	for (uint32_t k = 1; k<numEdgeServers; ++k){
        	Ptr<EdgeApp> serverApps = CreateObject<EdgeApp>();
		serverApps->Setup(InetSocketAddress(cloudInterfaces.GetAddress(2*k), port), port);
		edgeNodes.Get(k)->AddApplication(serverApps);
		serverApps->SetStartTime(Seconds(2.0));
		serverApps->SetStopTime(Seconds(simTime));
	}
	//This helps the packets route through the nodes properly
	Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    	//Configure graph and node mobility mode for NetAnim simulation
    	MobilityHelper mobility;
    	mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0), 
                                  "MinY", DoubleValue(0.0), 
                                  "DeltaX", DoubleValue(5.0), 
                                  "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(5), 
                                  "LayoutType", StringValue("RowFirst"));
    	mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    	mobility.Install(clients); mobility.Install(edgeNodes); mobility.Install(cloudNodes);
    	
    	//Capture all packets/data with Wireshark (see .pcap files)
	AsciiTraceHelper ascii;
	pp1.EnableAsciiAll(ascii.CreateFileStream("EdgeCompNorm.tr"));
	pp1.EnablePcapAll("EdgeCompNorm");
	
	//Simulate Edge Computing model using NetAnim, and configure nodes to specific locations of the graph
	AnimationInterface anim("edgeCompNorm.xml");
	uint32_t x_pos = 5;
	uint32_t clientImg = anim.AddResource("../../Pictures/Client.png");
	uint32_t edgeSvImg = anim.AddResource("../../Pictures/EdgeServer.png");
	uint32_t cloudSvImg= anim.AddResource("../../Pictures/CloudServer.png");
	for (uint32_t l = 0; l < numClients; ++l){
		ns3::AnimationInterface::SetConstantPosition(clients.Get(l), x_pos, 30); 
		anim.UpdateNodeImage(l, clientImg);
		anim.UpdateNodeSize(l, 3.0, 3.0);
		x_pos += 5;
	}
        x_pos = 10;
	for (uint32_t l = 0; l < numEdgeServers; ++l){
		ns3::AnimationInterface::SetConstantPosition(edgeNodes.Get(l), x_pos, 20); 
		anim.UpdateNodeImage(l+numClients, edgeSvImg);
		anim.UpdateNodeSize(l+numClients, 3.0, 3.0);
		x_pos += 10;
	}
	ns3::AnimationInterface::SetConstantPosition(cloudNodes.Get(0), 20, 10);
	anim.UpdateNodeImage(numClients+numEdgeServers, cloudSvImg);
	anim.UpdateNodeSize(numClients+numEdgeServers, 4.0, 4.0);
	Simulator::Stop(Seconds(simTime*2.0));
	Simulator::Run();
	Simulator::Destroy();
	return 0;
}


