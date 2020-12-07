cmake_minimum_required(VERSION 3.17)
project(forty_bytes
 VERSION 0.1
 LANGUAGES C CXX
 )

###
### Global Config
###
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-Wall -pedantic -Wextra)
elseif(MSVC)
    add_compile_options(/W4 /WX)
endif()

###
### Dependencies
###

# Internal libraries
add_subdirectory(lib)


# External libraries
find_package(OpenSSL 1.1 REQUIRED)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(PTLS REQUIRED)
message(STATUS "picotls/include: ${PTLS_INCLUDE_DIRS}" )
message(STATUS "picotls libraries: ${PTLS_LIBRARIES}" )
find_package(PICO REQUIRED)
message(STATUS "picoquic/include: ${PICO_INCLUDE_DIRS}" )
message(STATUS "picoquic libraries: ${PICO_LIBRARIES}" )


###
### Library Source
###

###
### Library Config
###

set(LIB_NAME "${PROJECT_NAME}")

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc")


add_library(${LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})
add_dependencies(${LIB_NAME} bytes)
target_link_libraries(${LIB_NAME} bytes ${PICO_LIBRARIES} ${PTLS_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(${LIB_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        ${PTLS_INCLUDE_DIRS}
        ${PICO_INCLUDE_DIRS}
        $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
        PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        )

###
### Applications
###

add_subdirectory(cmd)