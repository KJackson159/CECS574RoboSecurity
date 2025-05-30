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
#include <iomanip>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MAX_SIMULATION_TIME 10.0
#define RSA_BITS 2048
/*
CODE REFERENCES:
https://phdprime.com/how-to-simulate-edge-computing-projects-using-ns3/

https://ns3simulation.com/how-to-implement-end-to-end-encryption-in-ns3/#:~:text=To%20implement%20end-to-end,encryption%20and%20decryption%20of%20data

https://ns3simulation.com/how-to-implement-public-key-cryptography-in-ns3/

https://ns3simulation.com/how-to-implement-symmetric-key-cryptography-in-ns3/

https://ns3simulation.com/how-to-implement-edge-computing-security-in-ns3/

https://ns3simulation.com/how-to-implement-cryptographic-hashing-in-ns3/
*/
using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("EdgeCompE2EERSA");

/*--------------------------------||| RIVEST SHAMIR ADLEMAN (RSA) FUNCTIONS |||------------------------------------------------------------*/
//Generate RSA key pair per node
void GenerateRSAKeys(std::string &publicKey, std::string &privateKey) {
	RSA *rsa = RSA_new();  BIGNUM *bne = BN_new();
	BN_set_word(bne, RSA_F4);
	RSA_generate_key_ex(rsa, RSA_BITS, bne, NULL);
	
	BIO *pub = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(pub, rsa);
	size_t pub_len = BIO_pending(pub);
	char *pub_key = (char *)malloc(pub_len + 1);
	BIO_read(pub, pub_key, pub_len);
	pub_key[pub_len] = '\0';
	publicKey = std::string(pub_key);
	
	BIO *pri = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
	size_t pri_len = BIO_pending(pri);
	char *pri_key = (char *)malloc(pri_len + 1);
	BIO_read(pri, pri_key, pri_len);
	pri_key[pri_len] = '\0';
	privateKey = std::string(pri_key);
	
	BIO_free_all(pub); BIO_free_all(pri); RSA_free(rsa); BN_free(bne);
	free(pub_key); free(pri_key);
}

//Encrypt data using RSA public key
std::string EncryptWithPublicKey(const std::string &data, const std::string &publicKey) {
	RSA *rsa = RSA_new();
	BIO *keybio = BIO_new_mem_buf((void *)publicKey.c_str(), -1);
	PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

	std::string encryptedData(RSA_size(rsa), '\0');
	int encryptedLen = RSA_public_encrypt(data.size(), (const unsigned char *)data.c_str(),
	(unsigned char *)encryptedData.c_str(), rsa, RSA_PKCS1_OAEP_PADDING);

	BIO_free_all(keybio); RSA_free(rsa);
	if (encryptedLen == -1) {
		char err[130]; ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		std::cerr << "Encryption error: " << err << std::endl; return "";
	} return encryptedData;
}

//Decrypt data using RSA private key
std::string DecryptWithPrivateKey(const std::string &encryptedData, const std::string &privateKey) {
	RSA *rsa = RSA_new();
	BIO *keybio = BIO_new_mem_buf((void *)privateKey.c_str(), -1);
	PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	std::string decryptedData(RSA_size(rsa), '\0');
	int decryptedLen = RSA_private_decrypt(encryptedData.size(), (const unsigned char *)encryptedData.c_str(),
	(unsigned char *)decryptedData.c_str(), rsa, RSA_PKCS1_OAEP_PADDING);

	BIO_free_all(keybio); RSA_free(rsa);
	if (decryptedLen == -1) {
		char err[130]; ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		std::cerr << "Decryption error: " << err << std::endl; return "";
	} decryptedData.resize(decryptedLen);
	return decryptedData;
}

std::string ComputeSHA256(const std::string &data) {
	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, data.c_str(), data.size());
	SHA256_Final(hash, &sha256);
	
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	return ss.str();
}

//Sign/Encrypt hash using RSA private key
std::string SignWithPrivateKey(const std::string &hash, const std::string &privateKey) {
	RSA *rsa = RSA_new();
	BIO *keybio = BIO_new_mem_buf((void *)privateKey.c_str(), -1);
	PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	std::string encryptedHash(RSA_size(rsa), '\0');
	int encryptedLen = RSA_private_encrypt(hash.size(), (const unsigned char *)hash.c_str(),
	(unsigned char *)encryptedHash.c_str(), rsa, RSA_PKCS1_PADDING);

	BIO_free_all(keybio); RSA_free(rsa);
	if (encryptedLen == -1) {
		char err[130]; ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		std::cerr << "Encryption error: " << err << std::endl; return "";
	} return encryptedHash;
}

//Decrypt and verify hash using RSA public key
std::string VerifyWithPublicKey(const std::string &encryptedHash, const std::string &publicKey) {
	RSA *rsa = RSA_new();
	BIO *keybio = BIO_new_mem_buf((void *)publicKey.c_str(), -1);
	PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

	std::string decryptedHash(RSA_size(rsa), '\0');
	int decryptedLen = RSA_public_decrypt(encryptedHash.size(), (const unsigned char *)encryptedHash.c_str(),
	(unsigned char *)decryptedHash.c_str(), rsa, RSA_PKCS1_PADDING); //RSA_PKCS1_PADDING

	BIO_free_all(keybio); RSA_free(rsa);
	if (decryptedLen == -1) {
		char err[130]; ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		std::cerr << "Decryption error: " << err << std::endl; return "";
	} decryptedHash.resize(decryptedLen);
	return decryptedHash;
}

/*---------------------------------||| RSA CLASSES FOR CLIENT AND EDGE NODES |||-----------------------------------------------------------*/
//RSA Client application for chosen client node(s)
class RSAClient : public Application{
	public:
		RSAClient(){}
		virtual ~RSAClient(){}
		//Function Called to set up client node with RSA
		void Setup(Address address, uint16_t port, std::string publicKey, std::string privateKey, 
			   std::string message, Address sendToAddr){
			m_myAddress = address; m_peerPort = port;
			m_publicKey = publicKey; m_privateKey = privateKey;
			m_sendAddress = sendToAddr; m_message = message;
		}	
	private:
		virtual void StartApplication(){
			if(!m_socket) m_socket = Socket::CreateSocket(GetNode(), 
						  TypeId::LookupByName("ns3::UdpSocketFactory"));
			m_socket->Bind(m_myAddress); //Bind client's address to socket
			Simulator::Schedule(Seconds(1.0), &RSAClient::SendPacket, this); //Begin sending packets
			m_socket->SetRecvCallback(MakeCallback(&RSAClient::ReceivePacket, this)); //Allow retrieval of packets
		}
		virtual void StopApplication(){ //Dereference socket before ending app
			if (m_socket) {m_socket->Close(); m_socket=NULL;} NS_LOG_INFO("Socket Dereference Successful");
		}
		void SendPacket(){
			std::string encryptedMsg = EncryptWithPublicKey(m_message, m_publicKey);
			std::string hashedEncMsg = ComputeSHA256(encryptedMsg);
			std::string signature = SignWithPrivateKey(hashedEncMsg, m_privateKey);
			std::string signedMsg = encryptedMsg+":"+signature;
			Ptr<Packet> packet = Create<Packet>((uint8_t*)signedMsg.c_str(), signedMsg.size());
			if(m_socket){
				m_socket->SendTo(packet, 0, m_sendAddress);
				std::cout << "At time " << Simulator::Now() << ", " << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4() <<
				" sent encrypted msg to " << InetSocketAddress::ConvertFrom(m_sendAddress).GetIpv4() << std::endl;
				Simulator::Schedule(Simulator::Now(), &RSAClient::SendPacket, this);
			}
		}
		void ReceivePacket(Ptr<Socket> socket){
			Address from; //Receive encrypted message from edge server
			Ptr<Packet> packet = socket->RecvFrom(from);
			std::cout << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4() << " received encrypted msg from " 
			<< InetSocketAddress::ConvertFrom(from).GetIpv4() << " at " << Simulator::Now() << std::endl;
			uint8_t buffer[1024];
			packet->CopyData(buffer, packet->GetSize());
			std::string signedMessage((char*)buffer, packet->GetSize());
			
			size_t pos = signedMessage.find_last_of(':');
			std::string encryptedMsg = signedMessage.substr(0, pos);
			std::string recvHash = VerifyWithPublicKey(signedMessage.substr(pos+1), m_publicKey);
			std::cout << "Received hash: " << recvHash << "done" << std::endl;
			std::string verifHash = ComputeSHA256(encryptedMsg);
			std::cout << "Check hash: " << verifHash << "done" << std::endl;
			
			if(recvHash == verifHash){
				std::cout << "Hashes match!" << std::endl;
				std::string decryptedMsg = DecryptWithPrivateKey(encryptedMsg, m_privateKey);
				std::cout << "Decrypted msg: " << decryptedMsg << std::endl;
			}else std::cout << "Invalid msg from mismatched hash! Integrity at risk!" << std::endl << std::endl;
			/*
			std::string encryptedMessage((char*)buffer, packet->GetSize());
			std::string decryptedMessage = DecryptWithPrivateKey(encryptedMessage, m_privateKey);
			std::cout << "Decrypted msg: " << decryptedMessage << std::endl << std::endl;*/
		}
		Ptr<Socket> m_socket; Address m_myAddress, m_sendAddress; uint16_t m_peerPort;
		std::string m_publicKey, m_privateKey, m_sharedKey, m_message;
};

//RSA Edge application for chosen edge server node(s) as sink for encrypted messages
class RSAEdge : public Application{
	public:
		RSAEdge(){}
		virtual ~RSAEdge(){}
		//Function Called to set up edge node with RSA
		void Setup(Address address, uint16_t port, std::string publicKey, std::string privateKey, std::string message){
			m_myAddress = address; m_peerPort = port;
			m_publicKey = publicKey; m_privateKey = privateKey;
			m_message = message;
		}	
	private:
		virtual void StartApplication(){
			if(!m_socket) m_socket = Socket::CreateSocket(GetNode(), 
						  TypeId::LookupByName("ns3::UdpSocketFactory"));
			m_socket->Bind(m_myAddress); //Bind edge server's address to socket
			m_socket->SetRecvCallback(MakeCallback(&RSAEdge::ReceivePacket, this));
		}
		virtual void StopApplication(){
			if (m_socket) {m_socket->Close(); m_socket=NULL;} NS_LOG_INFO("Socket Dereference Successful");
		}
		void ReceivePacket(Ptr<Socket> socket){
			Address from; //Receive encrypted message from client
			Ptr<Packet> packet = socket->RecvFrom(from);
			std::cout << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4() << " received encrypted msg from " 
			<< InetSocketAddress::ConvertFrom(from).GetIpv4() << " at " << Simulator::Now() << std::endl;
			uint8_t buffer[1024];
			packet->CopyData(buffer, packet->GetSize());
			std::string signedMessage((char*)buffer, packet->GetSize());
			
			size_t pos = signedMessage.find_last_of(':');
			std::string encryptedMsg = signedMessage.substr(0, pos);
			std::string fromsignature = signedMessage.substr(pos+1);
			//std::cout << "Signature: " << fromsignature << "done" << std::endl;
			std::string recvHash = VerifyWithPublicKey(fromsignature, m_publicKey);
			std::cout << "Received hash: " << recvHash << "done" << std::endl;
			std::string verifHash = ComputeSHA256(encryptedMsg);
			std::cout << "Check hash: " << verifHash << "done" << std::endl;
			
			if(recvHash == verifHash){
				std::cout << "Hashes match!" << std::endl;
				std::string decryptedMsg = DecryptWithPrivateKey(encryptedMsg, m_privateKey);
				std::cout << "Decrypted msg: " << decryptedMsg << std::endl;
			}else std::cout << "Invalid msg from mismatched hash! Integrity at risk!" << std::endl;
			
			//Return an encrypted message to corresponding client
			std::string returnMsg = EncryptWithPublicKey(m_message, m_publicKey);
			std::string hashedEncMsg = ComputeSHA256(returnMsg);
			std::string signature = SignWithPrivateKey(hashedEncMsg, m_privateKey);
			std::string signedRMsg = returnMsg+":"+signature;
			
			Ptr<Packet> returnPkt = Create<Packet>((uint8_t*)signedRMsg.c_str(), signedRMsg.size());
			if(m_socket){
				m_socket->SendTo(returnPkt, 0, from);
				std::cout << "At time " << Simulator::Now() << ", " << InetSocketAddress::ConvertFrom(m_myAddress).GetIpv4() <<
				" sent encrypted msg to " << InetSocketAddress::ConvertFrom(from).GetIpv4() << std::endl<< std::endl; 
			}
		}
		Ptr<Socket> m_socket; Address m_myAddress; uint16_t m_peerPort;
		std::string m_publicKey, m_privateKey, m_sharedKey, m_message;
};

/*--------------------------------||| NORMAL CLASSES FOR CLIENT AND EDGE NODES |||---------------------------------------------------------*/
//Normal Client application for each client node
class ClientApp : public Application{
	public:
		ClientApp(){}
		virtual ~ClientApp(){}
		void Setup(Address address, uint16_t port, std::string message, Address nextAddr)
		{	m_myAddress = address; m_peerPort = port; m_message = message; m_sendAddress = nextAddr;	}
	private:
		virtual void StartApplication(){
			if(!m_socket) m_socket = Socket::CreateSocket(GetNode(), 
						  TypeId::LookupByName("ns3::UdpSocketFactory"));
			m_socket->Bind(m_myAddress);
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

//Normal Edge application for chosen edge server node as sink
class EdgeApp : public Application {
	public:
		EdgeApp() {}
		virtual ~EdgeApp() {}
		void Setup(Address address, uint16_t port)
		{	m_myAddress = address; m_peerPort = port; 	}
	private:
		virtual void StartApplication() {
			if(!m_socket) m_socket = Socket::CreateSocket(GetNode(), 
						  TypeId::LookupByName("ns3::UdpSocketFactory"));
			m_socket->Bind(m_myAddress);
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

/*------------------------------------||| MAIN FUNCTION TO EXECUTE ALL CODE |||------------------------------------------------------------*/
int main(int argc, char *argv[]) {
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
	
	//Assign messages for RSA client and RSA edge nodes
	std::string msg1 = "This is a SECURE msg from client node 1";
	std::string msg2 = "This is a SECURE msg from edge node 3"; //"This is a SECURE msg from client node 9";
	//Generate key pairs for both nodes
	std::string pubK1, privK1, pubK2, privK2;
	GenerateRSAKeys(pubK1, privK1); GenerateRSAKeys(pubK2, privK2);
	
	//Set up sockets for custom packets to travel
	uint16_t port = 8080;
	//NOTE: public keys already swapped, but in real life, they must be swapped via network comm.
	Ptr<RSAClient> clientApp = CreateObject<RSAClient>();
	clientApp->Setup(InetSocketAddress(edgeInterfaces.GetAddress(0), port), port, pubK2, privK1, msg1,
			 InetSocketAddress(cloudInterfaces.GetAddress(4), port));
	clients.Get(0)->AddApplication(clientApp);
	clientApp->SetStartTime(Seconds(1.0));
	clientApp->SetStopTime(Seconds(simTime));
	
	Ptr<RSAEdge> edgeApp = CreateObject<RSAEdge>();
	edgeApp->Setup(InetSocketAddress(cloudInterfaces.GetAddress(4), port), port, pubK1, privK2, msg2);
	edgeNodes.Get(2)->AddApplication(edgeApp);
	edgeApp->SetStartTime(Seconds(2.0));
	edgeApp->SetStopTime(Seconds(simTime));
	
	//The remaining nodes don't use RSA
	for (uint32_t k = 1; k<numClients; ++k){
		std::stringstream msg3;
		msg3 << "This is a normal msg from client node " << k+1;
        	Ptr<ClientApp> clientApps = CreateObject<ClientApp>();
		clientApps->Setup(InetSocketAddress(edgeInterfaces.GetAddress(2*k), port), port, msg3.str(),
				InetSocketAddress(cloudInterfaces.GetAddress(2), port));
		clients.Get(k)->AddApplication(clientApps);
		clientApps->SetStartTime(Seconds(1.0));
		clientApps->SetStopTime(Seconds(simTime));
		//if(k+1==8) k++;
	}
	
        Ptr<EdgeApp> serverApps = CreateObject<EdgeApp>();
	serverApps->Setup(InetSocketAddress(cloudInterfaces.GetAddress(2), port), port);
	edgeNodes.Get(1)->AddApplication(serverApps);
	serverApps->SetStartTime(Seconds(2.0));
	serverApps->SetStopTime(Seconds(simTime));
	
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
	pp1.EnableAsciiAll(ascii.CreateFileStream("E2EE.tr"));
	pp1.EnablePcapAll("E2EE");
	
	//Simulate Edge Computing model using NetAnim, and configure nodes to specific locations of the graph
	AnimationInterface anim("E2EE.xml");
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
