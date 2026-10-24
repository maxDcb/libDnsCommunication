cmake_minimum_required(VERSION 3.24 FATAL_ERROR)
project(Dnscommunication VERSION 0.0.0 LANGUAGES CXX C)

include(CTest)

set(CMAKE_CXX_STANDARD 23)

option(DNS_ENABLE_LOGGING "Enable debug logging output" OFF)

set(SOURCE_FILES
src/message.cpp
src/query.cpp
src/response.cpp
src/dns.cpp
src/server.cpp
src/client.cpp
src/dnsPacker.cpp
)


add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
set_property(TARGET ${PROJECT_NAME} PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(${PROJECT_NAME} )
target_include_directories(${PROJECT_NAME} PUBLIC src)
if(DNS_ENABLE_LOGGING)
    target_compile_definitions(${PROJECT_NAME} PUBLIC DNS_ENABLE_LOGGING)
endif()
if(WIN32)
        target_compile_definitions(${PROJECT_NAME} PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
        target_link_libraries(${PROJECT_NAME} ws2_32)
else()
        target_link_libraries(${PROJECT_NAME} pthread)
endif()


add_executable(publicDnsClient "examples/public_dns_client.cpp" )
set_property(TARGET publicDnsClient PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
        target_link_libraries(publicDnsClient Dnscommunication)
else()
        target_link_libraries(publicDnsClient Dnscommunication pthread)
endif()


if(BUILD_TESTING)
        add_subdirectory(tests)
endif()
