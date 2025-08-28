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


add_executable(fonctionalTest "fonctional_test.cpp" )
set_property(TARGET fonctionalTest PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
        target_link_libraries(fonctionalTest Dnscommunication)
else()
        target_link_libraries(fonctionalTest Dnscommunication pthread)
endif()


add_executable(responseDecodeTest "response_decode_test.cpp" )
set_property(TARGET responseDecodeTest PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
        target_link_libraries(responseDecodeTest Dnscommunication)
else()
        target_link_libraries(responseDecodeTest Dnscommunication pthread)
endif()


add_executable(messageTest "message_test.cpp" )
set_property(TARGET messageTest PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
        target_link_libraries(messageTest Dnscommunication)
else()
        target_link_libraries(messageTest Dnscommunication pthread)
endif()