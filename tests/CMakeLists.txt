add_executable(testsDns "main.cpp" )
set_property(TARGET testsDns PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(testsDns Dnscommunication )


