
add_executable(server echoServer.cc)
target_link_libraries( server PUBLIC forty_bytes)


add_executable( client client.cc)
target_link_libraries( client PUBLIC forty_bytes)
