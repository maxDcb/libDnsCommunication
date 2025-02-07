add_executable(testsDns "main.cpp" )
set_property(TARGET testsDns PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
	target_link_libraries(testsDns Dnscommunication)
else()
	target_link_libraries(testsDns Dnscommunication pthread)
endif()
