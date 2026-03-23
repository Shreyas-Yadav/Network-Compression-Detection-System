/* udp_server.c - A UDP server for network probing experiments.
   This server processes high and low entropy network packet trains
   to detect network traffic manipulation.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <jansson.h>
#include <errno.h>
#include <sys/select.h>

/* Maximum size for network buffers */
#define BUFFER_SIZE 5000
/* Timeout in seconds for high entropy train after first packet captured */
#define TIMEOUT_HIGH 7   
/* Timeout in seconds for low entropy train after first packet captured */
#define TIMEOUT_LOW  7   
/* Timeout in seconds for post-probing phase waiting for client connection */
#define TIMEOUT_POST 15   

/* Save received JSON data to a file.
   The function overwrites any existing file with the new data.
   json_data: The JSON data string to save to file.
*/
void save_json_to_file(const char *json_data)
{
    FILE *file = fopen("received_data.json", "w"); // Overwrite each time
    if (file == NULL)
    {
        perror("File open failed");
        return;
    }
    fprintf(file, "%s", json_data); // Write JSON data
    fclose(file);
    // printf("JSON data saved to received_data.json\n");
}



/* Listen for incoming pre-probing configuration data over TCP.
   Receives JSON configuration data from a client and saves it to a file.
   port_number: TCP port to listen on for the configuration data.
*/
void pre_probing_listen(uint16_t port_number)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];
    char *json_data = NULL;
    size_t total_received = 0;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int recv_buf_size = BUFFER_SIZE; 
    if (setsockopt(server_fd, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, sizeof(recv_buf_size)) < 0)
    {
        perror("Failed to set receive buffer size");
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_SNDBUF, &recv_buf_size, sizeof(recv_buf_size)) < 0)
    {
        perror("Failed to set send buffer size");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_number);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0)
    {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    // printf("Server is listening on port %d...\n", port_number);

    client_len = sizeof(client_addr);
    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0)
    {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // printf("Connection established with client: %s\n", inet_ntoa(client_addr.sin_addr));
    json_data = malloc(1);
    if (json_data == NULL)
    {
        perror("Memory allocation failed");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    json_data[0] = '\0';

    while (1)
    {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received < 0)
        {
            perror("Recv failed");
            break;
        }
        else if (bytes_received == 0)
        {
            // printf("Client disconnected\n");
            break;
        }

        buffer[bytes_received] = '\0';
        char *temp = realloc(json_data, total_received + bytes_received + 1);
        if (temp == NULL)
        {
            perror("Memory reallocation failed");
            free(json_data);
            break;
        }
        json_data = temp;
        memcpy(json_data + total_received, buffer, bytes_received + 1);
        total_received += bytes_received;
    }

    if (total_received > 0)
    {
        save_json_to_file(json_data);
    }

    free(json_data);
    close(client_fd);
    close(server_fd);
}

/* Structure to store information about a packet train.
   Used to track timing and count of packets in a train.
*/
typedef struct {
    struct timespec first_packet_time; /* Timestamp of the first received packet */
    struct timespec last_packet_time;  /* Timestamp of the last received packet */
    int packet_count;                  /* Number of packets received */
    int expected_packet_count;         /* Expected number of packets */
    int last_packet_id;
} PacketTrainInfo;


/* Listen for and analyze incoming UDP packet trains.
   Measures time difference between high entropy and low entropy packet trains
   to detect potential network manipulation.
   
   expected_packet_count: Number of packets expected in each train.
   MAX_PACKET_SIZE: Maximum allowed size for incoming packets.
   server_port: UDP port to listen on for packet trains.
   
   Returns: 1 if time difference exceeds threshold (indicating manipulation),
            0 if no significant difference detected.
*/
uint16_t probing_phase_listen(uint16_t expected_packet_count, uint16_t MAX_PACKET_SIZE, uint16_t server_port)
{
    int udp_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[MAX_PACKET_SIZE];
    int packet_id;

    /* Create and bind UDP socket */
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        perror("UDP socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);
    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("UDP bind failed");
        exit(EXIT_FAILURE);
    }
    // printf("UDP server listening on port %d...\n", server_port);

    /* Process High Entropy Train using select()-based timeout starting at first packet capture */
    PacketTrainInfo high_entropy_train = {0};
    high_entropy_train.expected_packet_count = expected_packet_count;
    struct timespec deadline_high;
    int first_high = 1;
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(udp_socket, &readfds);

        struct timeval timeout;
        if (first_high && high_entropy_train.packet_count == 0) {
            /* If no packet has been received yet, wait indefinitely */
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            /* Compute remaining time for timeout (TIMEOUT_HIGH seconds after first packet) */
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double remaining = (deadline_high.tv_sec - now.tv_sec) +
                               (deadline_high.tv_nsec - now.tv_nsec) / 1e9;
            if (remaining <= 0) {
                // printf("High entropy train timeout reached after first packet. Switching to low entropy train.\n");
                break;
            }
            timeout.tv_sec = (int)remaining;
            timeout.tv_usec = (remaining - timeout.tv_sec) * 1e6;
        }

        int sel = select(udp_socket + 1, &readfds, NULL, NULL, (first_high && high_entropy_train.packet_count == 0) ? NULL : &timeout);
        if (sel == 0) {
            /* Timeout reached */
            // printf("High entropy train timeout reached. Switching to low entropy train.\n");
            break;
        } else if (sel < 0) {
            perror("Select error on high entropy train");
            continue;
        }

        int bytes_received = recvfrom(udp_socket, buffer, MAX_PACKET_SIZE, 0,
                                      (struct sockaddr *)&client_addr, &client_addr_len);
        if (bytes_received < 0) {
            perror("UDP recvfrom failed (high entropy)");
            continue;
        }
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);

        memcpy(&packet_id, buffer, 2);
        packet_id = ntohs(packet_id);

        if (high_entropy_train.packet_count == 0) {
            high_entropy_train.first_packet_time = current_time;
            /* Set deadline based on TIMEOUT_HIGH after first packet captured */
            deadline_high.tv_sec = current_time.tv_sec + TIMEOUT_HIGH;
            deadline_high.tv_nsec = current_time.tv_nsec;
        }
        high_entropy_train.packet_count++;
        high_entropy_train.last_packet_time = current_time;
        high_entropy_train.last_packet_id = packet_id;

        if (high_entropy_train.packet_count >= high_entropy_train.expected_packet_count) {
            // printf("Received all high entropy packets.\n");
            break;
        }
        first_high = 0;
    }

    /* Process Low Entropy Train using similar mechanism */
    PacketTrainInfo low_entropy_train = {0};
    low_entropy_train.expected_packet_count = expected_packet_count;
    struct timespec deadline_low;
    int first_low = 1;
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(udp_socket, &readfds);

        struct timeval timeout;
        if (first_low && low_entropy_train.packet_count == 0) {
            /* Wait indefinitely for the first packet */
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            /* Compute remaining time for timeout (TIMEOUT_LOW seconds after first packet) */
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double remaining = (deadline_low.tv_sec - now.tv_sec) +
                               (deadline_low.tv_nsec - now.tv_nsec) / 1e9;
            if (remaining <= 0) {
                printf("Low entropy train timeout reached after first packet. Ending low entropy capture.\n");
                break;
            }
            timeout.tv_sec = (int)remaining;
            timeout.tv_usec = (remaining - timeout.tv_sec) * 1e6;
        }

        int sel = select(udp_socket + 1, &readfds, NULL, NULL, (first_low && low_entropy_train.packet_count == 0) ? NULL : &timeout);
        if (sel == 0) {
            printf("Low entropy train timeout reached. Ending low entropy capture.\n");
            break;
        } else if (sel < 0) {
            perror("Select error on low entropy train");
            continue;
        }

        int bytes_received = recvfrom(udp_socket, buffer, MAX_PACKET_SIZE, 0,
                                      (struct sockaddr *)&client_addr, &client_addr_len);
        if (bytes_received < 0) {
            perror("UDP recvfrom failed (low entropy)");
            continue;
        }
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);

        memcpy(&packet_id, buffer, 2);
        packet_id = ntohs(packet_id);

        if (low_entropy_train.packet_count == 0) {
            low_entropy_train.first_packet_time = current_time;
            /* Set deadline based on TIMEOUT_LOW after first packet captured */
            deadline_low.tv_sec = current_time.tv_sec + TIMEOUT_LOW;
            deadline_low.tv_nsec = current_time.tv_nsec;
        }
        low_entropy_train.packet_count++;
        low_entropy_train.last_packet_time = current_time;
        low_entropy_train.last_packet_id = packet_id;

        if (low_entropy_train.packet_count >= low_entropy_train.expected_packet_count) {
            // printf("Received all low entropy packets.\n");
            break;
        }
        first_low = 0;
    }
    
    /* Calculate elapsed times for each train */
    double high_entropy_time = (high_entropy_train.last_packet_time.tv_sec - high_entropy_train.first_packet_time.tv_sec) +
                                (high_entropy_train.last_packet_time.tv_nsec - high_entropy_train.first_packet_time.tv_nsec) / 1e9;
    double low_entropy_time = (low_entropy_train.last_packet_time.tv_sec - low_entropy_train.first_packet_time.tv_sec) +
                               (low_entropy_train.last_packet_time.tv_nsec - low_entropy_train.first_packet_time.tv_nsec) / 1e9;

    printf("High entropy train time: %f seconds\n", high_entropy_time);
    printf("Low entropy train time: %f seconds\n", low_entropy_time);

    double time_difference = high_entropy_time - low_entropy_time;
    close(udp_socket);
    return (time_difference > 0.100) ? 1 : 0;
}

/* Retrieve configuration values from the JSON configuration file.
   
   obj_name: The name of the JSON object to access.
   attr_name: The name of the attribute within the object.
   
   Returns: The integer value of the requested attribute, or -1 if not found.
*/
uint16_t get_config_values(char *obj_name, char *attr_name)
{
    json_t *root;
    json_error_t error;
    root = json_load_file("received_data.json", 0, &error);
    if (!root) {
        fprintf(stderr, "Error opening or parsing JSON file: %s\n", error.text);
        exit(EXIT_FAILURE);
    }
    json_t *probing_obj = json_object_get(root, obj_name);
    json_t *attribute = json_object_get(probing_obj, attr_name);
    if (json_is_integer(attribute)) {
        return json_integer_value(attribute);
    } else {
        return -1;
    }
}

/* Send detection results back to the client over TCP.
   Listens for an incoming client connection and sends the
   probing result ("Yes" or "No").
   
   RESPONSE: The response string to send to the client.
   PORT: TCP port to listen on for client connection.
*/
void post_probing(char *RESPONSE, uint16_t PORT)
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // printf("Server listening on port %d for post probing (timeout %d seconds)...\n", PORT,TIMEOUT_POST);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(server_fd,&readfds);
    struct timeval timeout;

    timeout.tv_sec = TIMEOUT_POST;
    timeout.tv_usec = 0;

    int sel = select(server_fd + 1,&readfds,NULL,NULL,&timeout);

    if(sel == 0){
        printf("Post-probing phase timeout reached. No client connection recived.\n");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    else if(sel < 0){
        printf("Select error in post-probing phase");
        close(server_fd);
        exit(EXIT_FAILURE);
    }


    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    // printf("Client connected, sending response...\n");
    send(new_socket, RESPONSE, strlen(RESPONSE), 0);
    // printf("Response sent: %s\n", RESPONSE);
    close(new_socket);
    // printf("Client disconnected.\n");

    close(server_fd);
}

/* Main program function.
   Coordinates the three phases of the detection process:
   1. Pre-probing: Receive configuration data
   2. Probing: Analyze packet trains
   3. Post-probing: Send results back to client
   
   argc: Command line argument count
   argv: Command line arguments 
        argv[1] (optional): Port number to use for pre-probing configuration
*/
int main(int argc, char *argv[])
{
    int port_number = 7777;
    if (argc >= 2) {
        port_number = atoi(argv[1]);
    }

    pre_probing_listen(port_number);
    // printf("Pre probing phase completed\n");

    uint16_t packet_count = get_config_values("probing", "number_of_packets");
    uint16_t packet_size = get_config_values("probing", "packet_size");
    uint16_t server_port = get_config_values("probing", "UDP_destination_port");

    if (packet_count == -1 || packet_size == -1 || server_port == -1) {
        printf("Some values are missing in config file\n");
        exit(EXIT_FAILURE);
    }

    uint16_t response = probing_phase_listen(packet_count, packet_size, server_port);
    uint16_t post_server_port = get_config_values("post_probing", "port");

    if (response == 1) {
        post_probing("Yes", post_server_port);
    } else {
        post_probing("No", post_server_port);
    }
    return 0;
}