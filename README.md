# forty-bytes

This is a WIP repo to setup an example to use datagram client and server using picoquic.
NOTE: The example doesn't fully work yet !!

# Buillding
0. Needs C++17 an clang
1. Download and install picotls and picoquic 
2. In the same parent directory, clone this repo and run 
    - make all
    - make client
    - make server
    
    
    
# Notes
1. cmd/ - has client and server examples
2. src/transportMananger has application threads and queues (sender/receiver)
    for shuflfing data between the application and quic transport layer ( please see below)
3. src/netTransportQuic.cc implements picoquic transport thread
   which deals with creating sockets, read from application queue or from socket.
   
   
