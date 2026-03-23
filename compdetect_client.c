#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <jansson.h>
#include <time.h> 

/* Commented out default configuration. These values are now set in pre_probing_config()
// #define SERVER_IP "10.0.0.76"  // Localhost IP (You can change this to the server's IP)
// #define SERVER_PORT 7777
// #define FILE_PATH "config.json"
// #define BUFFER_SIZE 1024 
*/

/* Size of buffer used for file operations and network communications */
uint16_t BUFFER_SIZE = 1024;

/* Default port for pre-probing phase connection */
uint16_t PRE_PROBING_PORT = 7777;

/* Port for post-probing phase connection */
uint16_t POST_PROBING_PORT = 6666;

/* Port used during the probing server phase */
uint16_t PROBING_SERVER_PORT;

/* IP address of the server to connect to */
const char* SERVER_IP;


/* 
 * Send a file over a socket connection.
 * 
 * @param sock The socket descriptor to send data through
 * @param filename Path to the file to be sent
 */
void send_file(int sock, const char *filename) 
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    size_t bytesRead;

    /* Read file in chunks and send */
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (send(sock, buffer, bytesRead, 0) < 0) {
            perror("Error sending file");
            fclose(file);
            exit(EXIT_FAILURE);
        }
    }

    /* printf("File sent successfully.\n"); */
    fclose(file);
}

/*
 * Read configuration data from config.json file and set up pre-probing parameters.
 */
void pre_probing_config(){

    /* creating object to read json file */
    json_t *root;
    json_error_t error;

    /* reading config file */
    root = json_load_file("config.json",0,&error);

    if(!root){
        fprintf(stderr,"Error opening or parsing JSON file: %s\n",error.text);
        exit(EXIT_FAILURE);
    }

    /* setting default value for port and server IP address */
    PRE_PROBING_PORT = 10000;
    json_t *serverip = json_object_get(root,"server_ip");

    /* setting server ip address */
    if(json_is_string(serverip)){
        SERVER_IP = json_string_value(serverip);
    }
    else{
        perror("Invalid format for IP address. Please use string format");
        exit(EXIT_FAILURE);
    }

    /* setting port for per-probing connection */
    json_t *pre_probing_obj = json_object_get(root,"pre_probing");
    if(json_is_object(pre_probing_obj)){
        json_t *client_port_obj = json_object_get(pre_probing_obj,"client_port");
        if(json_is_integer(client_port_obj)){
            PRE_PROBING_PORT = json_integer_value(client_port_obj);
            /* printf("Port number : %d\n",PRE_PROBING_PORT); */
        }
    }
}


/*
 * Perform the pre-probing phase by connecting to the server and sending the config file.
 * 
 * @param file_path Path to the configuration file to send
 */
void pre_probing(char* file_path)
{
    int sock;
    struct sockaddr_in server_addr;
    /* char message[1024]; */

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    /* Set server address information */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PRE_PROBING_PORT);
    /* printf("%s\n",SERVER_IP); */
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    /* Connect to the server */
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(1);
    }
    /* printf("Connected to server at %s:%d\n", SERVER_IP, PRE_PROBING_PORT); */

    /* sending config file to server */
    send_file(sock,file_path);
    close(sock);

}


/*
 * Log a message with the current timestamp.
 * 
 * @param message The message to log
 */
void log_timestamp(const char *message) {
    time_t now;
    time(&now);
    printf("\n[%s] %s\n", ctime(&now), message);
}

/*
 * Create and send a UDP packet with a packet ID and payload.
 * 
 * @param sockfd Socket descriptor to send through
 * @param server_addr Pointer to the server address structure
 * @param packet_id ID of the packet being sent
 * @param payload Data to send in the packet
 * @param PAYLOAD_SIZE Size of the payload in bytes
 */
void send_udp_packet(int sockfd, struct sockaddr_in *server_addr, uint16_t packet_id, char *payload,uint16_t PAYLOAD_SIZE) {
    char packet[PAYLOAD_SIZE + sizeof(uint16_t)]; /* 2 bytes for packet ID */
    memset(packet, 0, sizeof(packet));

    /* Convert packet ID to network byte order and copy to the packet */
    uint16_t packet_id_network = htons(packet_id);
    memcpy(packet, &packet_id_network, sizeof(packet_id_network));

    /* Copy data payload */
    memcpy(packet + sizeof(uint16_t), payload, PAYLOAD_SIZE);

    /* Send the packet and check for errors */
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("Send failed");
    }
}


/*
 * Perform the probing phase by sending both high and low entropy UDP packets.
 * 
 * @param PAYLOAD_SIZE Size of each packet payload
 * @param SRC_PORT Source port for UDP packets
 * @param DEST_PORT Destination port for UDP packets
 * @param NUM_PACKETS Number of packets to send
 * @param INTER_MEASUREMENT_TIME Time in seconds between high and low entropy packet bursts
 */
void probing_phase(uint16_t PAYLOAD_SIZE,uint16_t SRC_PORT ,uint16_t DEST_PORT, uint16_t NUM_PACKETS, uint16_t INTER_MEASUREMENT_TIME)
{
    int sockfd;
    PAYLOAD_SIZE-=2;
    struct sockaddr_in server_addr, client_addr;
    char low_entropy_payload[PAYLOAD_SIZE];
    char high_entropy_payload[PAYLOAD_SIZE];

    /* Create UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    /* Bind the socket to source port */
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(SRC_PORT);  /* Set source port */

    if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    /* Configure server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEST_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &(server_addr.sin_addr)) <= 0) {
        perror("Invalid server IP");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    /* Prepare low entropy payload (all zeros) */
    memset(low_entropy_payload, 0, PAYLOAD_SIZE);

    /* Prepare high entropy payload (random data) */
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        perror("Failed to open /dev/urandom");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (fread(high_entropy_payload, 1, PAYLOAD_SIZE, urandom) != PAYLOAD_SIZE) {
        perror("Failed to read enough random data");
        fclose(urandom);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    fclose(urandom);

    /* Send high entropy packets */
    for (uint16_t i = 0; i < NUM_PACKETS; i++) {
        send_udp_packet(sockfd, &server_addr, i, high_entropy_payload, PAYLOAD_SIZE);
    }
    
    /* Wait for inter-measurement time */
    
    sleep(INTER_MEASUREMENT_TIME);
    
    /* Send low entropy packets */
    for (uint16_t i = 0; i < NUM_PACKETS; i++) {
        send_udp_packet(sockfd, &server_addr, i, low_entropy_payload, PAYLOAD_SIZE);
    }
    
    /* Close socket */
    close(sockfd);
}

/*
 * Get a specific attribute value from the probing section of the configuration file.
 * 
 * @param attr_name Name of the attribute to retrieve
 * @return Value of the attribute or -1 if not found
 */
uint16_t get_probing_config_attr(char *attr_name){
    json_t *root;
    json_error_t error;

    root = json_load_file("config.json",0,&error);

    if(!root){
        fprintf(stderr,"Error opening or parsing JSON file: %s\n",error.text);
        exit(EXIT_FAILURE);
    }

    json_t *probing_obj = json_object_get(root,"probing");

    json_t * attribute = json_object_get(probing_obj,attr_name);
    if(json_is_integer(attribute)){
        return json_integer_value(attribute);
    }
    else{
        return -1;
    }

}


/*
 * Perform the post-probing phase by connecting to the server and receiving the compression detection result.
 * 
 * @return Message from the server indicating compression status
 */
char* post_probing()
{
    int sock;
    struct sockaddr_in server_addr;
    char *message = (char *)malloc(BUFFER_SIZE);
    if (message == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        free(message);
        exit(1);
    }
    
    /* Set server address information */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(POST_PROBING_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    /* Connect to the server */
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        free(message);
        exit(1);
    }

    /* Read data from the server */
    ssize_t bytesRead = read(sock, message, BUFFER_SIZE - 1);
    if (bytesRead < 0) {
        perror("Error reading from socket");
        close(sock);
        free(message);
        exit(1);
    }

    message[bytesRead] = '\0'; /* Null-terminate the received message */
    close(sock);
    return message;
}


/*
 * Main function that orchestrates the compression detection process.
 * 
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return 0 on success, 1 on failure
 */
int main(int argc,char *argv[]) {

    if(argc != 2){
        printf("Please provide configuration file path");
        exit(EXIT_FAILURE);
    }
    char* path = argv[1];

    /* Pre-probing phase */
    pre_probing_config();
    pre_probing(path);
    /* printf("Pre-probing phase completed successfully\n"); */

    /* to prepapre server for UDP transmission */
    sleep(5);

    uint16_t payload_size = get_probing_config_attr("packet_size");
    uint16_t destination_port = get_probing_config_attr("UDP_destination_port");
    uint16_t source_port = get_probing_config_attr("UDP_source_port");
    uint16_t number_of_packets = get_probing_config_attr("number_of_packets");
    uint16_t inter_mesurement_time = get_probing_config_attr("inter_measurement_time");    
    probing_phase(payload_size,source_port,destination_port,number_of_packets,inter_mesurement_time);
    /* printf("Probing phase completed\n"); */


    /* to preapre for post probing phase */
    sleep(5);

    
    char* messgae = post_probing();
    /* printf("%ld\n",strlen(messgae)); */
    /* printf("%s\n",messgae); */
    if(strlen(messgae) == 2){
        printf("No compression detected\n");
    }
    else{
        printf("Compression Detected\n");
    }
    return 0;
}