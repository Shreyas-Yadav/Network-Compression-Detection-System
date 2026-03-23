/* compdetect.c - Network compression detection tool
   This program detects if network compression is being applied by sending
   high and low entropy packet trains and measuring timing differences in
   RST packet responses.  
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <jansson.h>


#define PSEUDO_HEADER_SIZE 12
#define client_port 12345
#define RST_COUNT 4
#define RST_LISTEN_TIMEOUT 60
#define THRSHHOLD 0.100



const char* server_ip;
const char* client_ip;

// setting default values
int server_head_port = 9999;
int server_tail_port = 8888;
int INTERMEASUREMENT_TIME = 15;
int PACKET_COUNT = 6000;

int PAYLOAD_SIZE = 1000;
int TTL = 255;
int DEST_PORT = 8765;
int SRC_PORT = 9876;


/* Structure for TCP pseudo header used in checksum calculation */
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


/* 
 * Load configuration from JSON file.
 *
 * Parse the JSON configuration file to extract server IP, client IP, and other
 * parameters to be used for the compression detection test.
 *
 * path: Path to the JSON configuration file
 */
void get_config(char* path){
    json_t *root;
    json_error_t error;

    root = json_load_file(path,0,&error);

    if(!root){
        fprintf(stderr,"Error opening or parsing JSON file: %s\n",error.text);
        exit(EXIT_FAILURE);
    }

    json_t *serverip = json_object_get(root,"server_ip");
    json_t *cleintip = json_object_get(root,"client_ip");
    if(json_is_string(serverip)){
        server_ip = json_string_value(serverip);
    }
    else{
        perror("Invalid format for server IP address. Please use string format");
        exit(EXIT_FAILURE);
    }

    if(json_is_string(cleintip)){
        client_ip = json_string_value(cleintip);
    }
    else{
        perror("Invalid format for client IP address. Please use string format");
        exit(EXIT_FAILURE);
    }

    json_t *standalone = json_object_get(root,"standalone");

    json_t *tcp_head_port = json_object_get(standalone,"TCP_HEAD_PORT");
    json_t *tcp_tail_port = json_object_get(standalone,"TCP_TAIL_PORT");
    json_t *payload_size = json_object_get(standalone,"UDP_PAYLOAD_SIZE");
    json_t *ttl = json_object_get(standalone,"TTL");
    json_t *dest_port = json_object_get(standalone,"UDP_DST_PORT");
    json_t *src_port = json_object_get(standalone,"UDP_SRC_PORT");
    json_t *inter_measurement_time = json_object_get(standalone,"inter_measurement_time");

    json_t *num_packet = json_object_get(standalone,"NUM_PACKETS");



    if(json_is_integer(tcp_head_port)){
        server_head_port = json_integer_value(tcp_head_port);
    }

    if(json_is_integer(tcp_tail_port)){
        server_tail_port = json_integer_value(tcp_tail_port);
    }


    if(json_is_integer(payload_size)){
        PAYLOAD_SIZE = json_integer_value(payload_size);
    }

    if(json_is_integer(ttl)){
        TTL = json_integer_value(ttl);
    }


    if(json_is_integer(dest_port)){
        DEST_PORT = json_integer_value(dest_port);
    }


    if(json_is_integer(src_port)){
        SRC_PORT = json_integer_value(src_port);
    }

    if(json_is_integer(inter_measurement_time)){
        INTERMEASUREMENT_TIME = json_integer_value(inter_measurement_time);
    }

    if(json_is_integer(num_packet)){
        PACKET_COUNT = json_integer_value(num_packet);
    }

}


/*
 * Calculate checksum for IP and TCP headers.
 *
 * This function calculates the checksum used in IP and TCP headers to ensure
 * packet integrity during transmission.
 *
 * b: Pointer to the data buffer
 * len: Length of the data in bytes
 *
 * Returns: The calculated checksum value
 */
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/*
 * Send a TCP SYN packet to a specified destination.
 *
 * Creates and sends a TCP SYN packet to initiate a connection to the specified
 * destination. Used to mark the beginning and end of packet trains.
 *
 * src_ip: Source IP address
 * dst_ip: Destination IP address
 * src_port: Source port number
 * dst_port: Destination port number
 */
void send_syn_packet(const char *src_ip, const char *dst_ip, int src_port, int dst_port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dst_port);
    dest_addr.sin_addr.s_addr = inet_addr(dst_ip);
    
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(packet));
    ip_header->id = htonl(rand() % 65535);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->saddr = inet_addr(src_ip);
    ip_header->daddr = inet_addr(dst_ip);
    ip_header->check = checksum(ip_header, sizeof(struct iphdr));
    
    tcp_header->source = htons(src_port);
    tcp_header->dest = htons(dst_port);
    tcp_header->seq = htonl(rand());
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->syn = 1;
    tcp_header->window = htons(65535);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;
    
    struct pseudo_header psh;
    psh.source_address = inet_addr(src_ip);
    psh.dest_address = inet_addr(dst_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    
    char pseudo_packet[PSEUDO_HEADER_SIZE + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, PSEUDO_HEADER_SIZE);
    memcpy(pseudo_packet + PSEUDO_HEADER_SIZE, tcp_header, sizeof(struct tcphdr));
    
    tcp_header->check = checksum(pseudo_packet, sizeof(pseudo_packet));
    
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Packet send failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    close(sock);
}

/*
 * Thread function that captures RST packets and detects compression.
 * 
 * This function listens for RST packets, timestamps them, and uses the timing
 * differences to determine if compression is being applied in the network.
 * 
 * Returns: NULL pointer (pthread requirement)
 */
void *capture_rst_packet() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    char buffer[65536];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    struct timespec RST[4];

    struct timeval start,cur;
    gettimeofday(&start,NULL);

    // printf("Listening for RST packets\n");
    int count = 0;
    while (1) {
        gettimeofday(&cur,NULL);
        if(cur.tv_sec - start.tv_sec >= RST_LISTEN_TIMEOUT){
            printf("Failed to detect due to insufficent information\n");
            exit(EXIT_FAILURE);
        }
        int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
        clock_gettime(CLOCK_MONOTONIC,&RST[count]);
        if (bytes_received < 0) {
            perror("Packet receive failed");
            close(sock);
            exit(EXIT_FAILURE);
        }

        struct iphdr *ip_header = (struct iphdr *)buffer;
        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl * 4));
            if (tcp_header->rst) 
            {
                // printf("RST Captured");
                count++;
            }

            if (count == 4)
            {
                break;
            }
            
        }
    }


    double high_diff = (RST[1].tv_sec - RST[0].tv_sec) + (RST[1].tv_nsec - RST[0].tv_nsec)/1e9;
    double low_diff = (RST[3].tv_sec - RST[2].tv_sec) + (RST[3].tv_nsec - RST[2].tv_nsec)/1e9;
    double total_diff = (high_diff-low_diff);
    

    // printf("Total Diff: %f\n",total_diff);
    

    if(total_diff < THRSHHOLD){
        printf("No compression detected\n");
    }
    else{
        printf("Compression detected\n");
    }
    

    close(sock);
    return NULL;
}


/*
 * Calculate UDP checksum.
 *
 * Calculates the checksum for UDP packets to ensure data integrity.
 *
 * ptr: Pointer to the data buffer
 * nbytes: Length of the data in bytes
 *
 * Returns: The calculated checksum value
 */
unsigned short calculate_udp_checksum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    unsigned short oddbyte;
    register short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    
    return answer;
}

/* 
 * Structure for UDP pseudo header used in checksum calculation.
 * This is not part of the actual UDP packet but is used to compute the checksum.
 */
struct pseudo_udp_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};


/*
 * Send a train of high entropy UDP packets.
 *
 * Creates and sends a specified number of UDP packets with high entropy
 * (random) payloads to test compression effects.
 *
 * high_entropy_count: Number of high entropy packets to send
 *
 * Returns: 0 on success, 1 on failure
 */
int send_high_entropy_train(int high_entropy_count){
    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // Prepare packet buffer
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE];
    
    // Get destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    
    if (inet_pton(AF_INET, server_ip, &dest.sin_addr) <= 0) {
        perror("Invalid destination IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // Setup IP header
    struct iphdr *ip_header = (struct iphdr *)packet;
    memset(ip_header, 0, sizeof(struct iphdr));
    
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE;
    ip_header->id = htons(rand());
    ip_header->frag_off = htons(0x4000);
    ip_header->ttl = TTL;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(client_ip);
    ip_header->daddr = dest.sin_addr.s_addr;
    
    // Setup UDP header
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
    udp_header->source = htons(SRC_PORT);
    udp_header->dest = htons(DEST_PORT);
    udp_header->len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
    udp_header->check = 0;
    
    // Payload pointer
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Open /dev/urandom for high entropy data
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0) {
        perror("Failed to open /dev/urandom");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    

    
    // Send high entropy packets
    for (int i = 0; i < high_entropy_count; i++) {
        // Reset packet to avoid any previous data
        memset(payload, 0, PAYLOAD_SIZE);
        
        // First 2 bytes are the index number
        payload[0] = (i >> 8) & 0xFF;  // High byte of index
        payload[1] = i & 0xFF;         // Low byte of index
        
        // Fill the rest with data from /dev/urandom
        if (read(urandom_fd, payload + 2, PAYLOAD_SIZE - 2) < PAYLOAD_SIZE - 2) {
            perror("Failed to read from /dev/urandom");
            close(urandom_fd);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        
        // Recalculate IP checksum
        ip_header->check = 0;
        ip_header->check = calculate_udp_checksum((unsigned short *)ip_header, sizeof(struct iphdr));
        
        // Calculate UDP checksum (optional but recommended)
        struct pseudo_udp_header psh;
        psh.source_address = inet_addr(client_ip);
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
        
        // Prepare checksum buffer
        char *pseudo_packet = malloc(sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + PAYLOAD_SIZE);
        memcpy(pseudo_packet, &psh, sizeof(struct pseudo_udp_header));
        memcpy(pseudo_packet + sizeof(struct pseudo_udp_header), udp_header, sizeof(struct udphdr) + PAYLOAD_SIZE);
        
        udp_header->check = 0;
        udp_header->check = calculate_udp_checksum((unsigned short *)pseudo_packet, sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + PAYLOAD_SIZE);
        free(pseudo_packet);
        
        // Send the packet
        if (sendto(sockfd, packet, ip_header->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Failed to send packet");
            close(urandom_fd);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        
        
        
    }
    close(urandom_fd);
    return 0;  
}


/*
 * Send a train of low entropy UDP packets.
 *
 * Creates and sends a specified number of UDP packets with low entropy
 * (all zeros) payloads to test compression effects.
 *
 * low_entropy_count: Number of low entropy packets to send
 *
 * Returns: 0 on success, 1 on failure
 */
int send_low_entropy_train(int low_entropy_count){
    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // Prepare packet buffer
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE];
    
    // Get destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    
    if (inet_pton(AF_INET, server_ip, &dest.sin_addr) <= 0) {
        perror("Invalid destination IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // Setup IP header
    struct iphdr *ip_header = (struct iphdr *)packet;
    memset(ip_header, 0, sizeof(struct iphdr));
    
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE;
    ip_header->id = htons(rand());
    ip_header->frag_off = htons(0x4000);
    ip_header->ttl = TTL;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(client_ip);
    ip_header->daddr = dest.sin_addr.s_addr;
    
    // Setup UDP header
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
    udp_header->source = htons(SRC_PORT);
    udp_header->dest = htons(DEST_PORT);
    udp_header->len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
    udp_header->check = 0;
    
    // Payload pointer
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    
    // Send low entropy packets (all zeros)
    for (int i = 0; i < low_entropy_count; i++) {
        // Reset payload to all zeros
        memset(payload, 0, PAYLOAD_SIZE);
        
        // First 2 bytes are the index number
        payload[0] = (i >> 8) & 0xFF;  // High byte of index
        payload[1] = i & 0xFF;         // Low byte of index
        
        // Rest of the payload is already zeros
        
        // Recalculate IP checksum
        ip_header->check = 0;
        ip_header->check = calculate_udp_checksum((unsigned short *)ip_header, sizeof(struct iphdr));
        
        // Calculate UDP checksum
        struct pseudo_udp_header psh;
        psh.source_address = inet_addr(client_ip);
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
        
        // Prepare checksum buffer
        char *pseudo_packet = malloc(sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + PAYLOAD_SIZE);
        memcpy(pseudo_packet, &psh, sizeof(struct pseudo_udp_header));
        memcpy(pseudo_packet + sizeof(struct pseudo_udp_header), udp_header, sizeof(struct udphdr) + PAYLOAD_SIZE);
        
        udp_header->check = 0;
        udp_header->check = calculate_udp_checksum((unsigned short *)pseudo_packet, sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + PAYLOAD_SIZE);
        free(pseudo_packet);
        
        // Send the packet
        if (sendto(sockfd, packet, ip_header->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Failed to send packet");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        
      
    }
    
    close(sockfd);
    return 0;    
}

/*
 * Generic function to send either high or low entropy UDP packet train.
 *
 * flag: 1 for high entropy, 0 for low entropy
 * packet_count: Number of packets to send
 *
 * Returns: Result from the specific send function
 */
void send_udp_train(int flag,int packet_count){
    if(flag){
        send_high_entropy_train(packet_count);
    }
    else{
        send_low_entropy_train(packet_count);
    }
}


/*
 * Main function - orchestrates the compression detection process.
 *
 * The program performs the following steps:
 * 1. Reads configuration from a JSON file
 * 2. Starts a thread to listen for RST packets
 * 3. Sends high entropy packets to test compression
 * 4. Waits for a specified time
 * 5. Sends low entropy packets to test compression
 * 6. Analyzes timing differences to detect compression
 *
 * argc: Argument count
 * argv: Argument values (including config file path)
 *
 * Returns: 0 on successful execution
 */
int main(int argc, char *argv[]) {


    if(argc != 2){
        perror("Invalid arguments\n Usage : sudo ./compdetect <config json file path>");
        exit(EXIT_FAILURE);
    }

    char* path = argv[1];
 

    get_config(path);

    
    // creating thread which listens for RST packets
    pthread_t thread;
    int result = pthread_create(&thread, NULL, capture_rst_packet, NULL);
    if (result != 0) {
        perror("Listening thread creation failed");
        exit(EXIT_FAILURE);
    }

    // just to make sure server is listening
    sleep(2);

    send_syn_packet(client_ip,server_ip,client_port,server_head_port);
    send_high_entropy_train(PACKET_COUNT);
    send_syn_packet(client_ip, server_ip, client_port, server_tail_port);

    sleep(INTERMEASUREMENT_TIME);

    send_syn_packet(client_ip,server_ip,client_port,server_head_port);
    send_low_entropy_train(PACKET_COUNT);
    send_syn_packet(client_ip, server_ip, client_port, server_tail_port);

    pthread_join(thread, NULL);
    return 0;
}