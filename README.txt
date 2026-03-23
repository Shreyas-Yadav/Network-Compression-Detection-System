## Developer
Shreyas Suhas Yadav

## Files

*   **compdetect.c**: This is Standalone Application. It reads configuration from a JSON file, starts a thread to listen for RST packets, sends high and low entropy packets, and analyzes timing differences to detect compression.

*   **compdetect_client.c**: This program acts as a client that sends a configuration file to the server, performs a probing phase by sending high and low entropy UDP packets, and receives the compression detection result from the server.
*   **compdetect_server.c**: This program acts as a server that listens for incoming pre-probing configuration data over TCP, analyzes incoming UDP packet trains, and sends detection results back to the client over TCP.

*   **Makefile**: This file contains instructions for compiling the project.
*   **config.json**: This file contains configuration parameters such as server and client IP addresses, ports, and packet counts.

## Usage

To compile and run the code, you need to have `gcc` and `jansson` library installed.

1.  Install the `jansson` library.
    *   For Debian/Ubuntu systems:
        ```bash
        sudo apt-get update
        sudo apt-get install libjansson-dev
        ```
    *   For Fedora/CentOS/RHEL systems:
        ```bash
        sudo yum install jansson-devel
        ```
2.  Compile the code using the `Makefile`.
    *   Run `make` to compile the `compdetect`, `compdetect_client`, and `compdetect_server` programs. This command uses the `gcc` compiler to create executable files from the corresponding `.c` source files, linking with the `jansson` and `pthread` libraries as needed.
        ```bash
        make
        ```
    *   Run `make clean` to remove the compiled executable files (`compdetect`, `compdetect_client`, and `compdetect_server`). This command helps to clean up the project directory.
        ```bash
        make clean
        ```
3.  Run the `compdetect` program with the path to the configuration file as an argument. You need to run it with sudo privileges.
    ```bash
    sudo ./compdetect config.json
    ```
4.  Run the `compdetect_client` program with the path to the configuration file as an argument.
    ```bash
    ./compdetect_client config.json
    ```
5.  Run the `compdetect_server` program, optionally providing a port number for pre-probing configuration.
    ```bash
    ./compdetect_server [port_number]
    ```

# Note
set same port number which you are passing to compdetect_server for "client_port" in "pre_probing" object in config.json.

## Configuration
The `config.json` file contains the following parameters:

*   `server_ip`: The IP address of the server.
*   `client_ip`: The IP address of the client.
*   `standalone`:
    *   `TCP_HEAD_PORT`: The TCP port for the head of the packet train.
    *   `TCP_TAIL_PORT`: The TCP port for the tail of the packet train.
    *   `UDP_PAYLOAD_SIZE`: The size of the UDP payload.
    *   `TTL`: The TTL value for the IP packets.
    *   `UDP_DST_PORT`: The destination port for UDP packets.
    *   `UDP_SRC_PORT`: The source port for UDP packets.
    *   `inter_measurement_time`: The time between sending high and low entropy packets.
    *   `NUM_PACKETS`: The number of packets to send in each train.
*   `pre_probing`:
    *   `client_port`: The TCP port for the client to connect to the server for pre-probing.
*   `probing`:
    *   `packet_size`: The size of the UDP packet payload.
    *   `UDP_destination_port`: The destination port for UDP packets during the probing phase.
    *   `UDP_source_port`: The source port for UDP packets during the probing phase.
    *   `number_of_packets`: The number of UDP packets to send during the probing phase.
    *   `inter_measurement_time`: The time between sending high and low entropy packets during the probing phase.
*   `post_probing`:
    *   `port`: The TCP port for the server to listen on for post-probing client connections.