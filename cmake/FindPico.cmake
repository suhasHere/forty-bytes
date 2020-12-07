# - Try to find Picoquic

find_path(PICO_INCLUDE_DIR
    NAMES picoquic.h
    HINTS ${CMAKE_SOURCE_DIR}/../picoquic/picoquic
          ${CMAKE_BINARY_DIR}/../picoquic/picoquic
          ../picoquic/picoquic)

set(PICO_HINTS ${CMAKE_BINARY_DIR}/../picoquic ../picoquic)

find_library(PICO_CORE_LIBRARY picoquic-core HINTS ${PICO_HINTS})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set PICO_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(PICO REQUIRED_VARS
    PICO_CORE_LIBRARY
    PICO_INCLUDE_DIR)

if(PICO_FOUND)
    set(PICO_LIBRARIES ${PICO_CORE_LIBRARY})
    set(PICO_INCLUDE_DIRS ${PICO_INCLUDE_DIR})
endif()

mark_as_advanced(PICO_LIBRARIES PICO_INCLUDE_DIRS)
