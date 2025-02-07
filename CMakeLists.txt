cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(Dnscommunication VERSION 0.0.0 LANGUAGES CXX C)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_STANDARD 17)

IF (WIN32)
    set(CMAKE_CXX_FLAGS_RELEASE "-MT -O1 -Ob0")
    set(CMAKE_C_FLAGS_RELEASE "-MT -O1 -Ob0")
ELSE()
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
ENDIF()


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
if(WIN32)
else()
	target_link_libraries(${PROJECT_NAME} pthread)
endif()


add_subdirectory(tests)