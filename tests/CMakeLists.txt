add_executable(testsDns "dns_test.cpp" )
set_property(TARGET testsDns PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
        target_link_libraries(testsDns Dnscommunication)
else()
        target_link_libraries(testsDns Dnscommunication pthread)
endif()

add_executable(utilsTest "utils_test.cpp" )
set_property(TARGET utilsTest PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
        target_link_libraries(utilsTest Dnscommunication)
else()
        target_link_libraries(utilsTest Dnscommunication pthread)
endif()
