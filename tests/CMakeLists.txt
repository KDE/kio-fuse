set( EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )
set(KIOFUSE_TEST_SOURCES
	fileopstest.cpp)

find_package(Qt5Test CONFIG REQUIRED)
find_package(Qt5DBus CONFIG REQUIRED)

qt5_add_dbus_interface(KIOFUSE_TEST_SOURCES org.kde.KIOFuse.VFS.xml kiofuse_interface)
qt5_add_dbus_interface(KIOFUSE_TEST_SOURCES org.kde.KIOFuse.Private.xml kiofuseprivate_interface)

add_executable(fileopstest-cache ${KIOFUSE_TEST_SOURCES})
target_link_libraries(fileopstest-cache PRIVATE Qt5::Test Qt5::DBus)
target_compile_definitions(fileopstest-cache PRIVATE -DTEST_CACHE_BASED_IO)
add_test(NAME fileopstest-cache COMMAND dbus-run-session ${CMAKE_BINARY_DIR}/bin/fileopstest-cache)
set_tests_properties(fileopstest-cache PROPERTIES ENVIRONMENT KDE_FORK_SLAVES=1)

add_executable(fileopstest-filejob ${KIOFUSE_TEST_SOURCES})
target_link_libraries(fileopstest-filejob PRIVATE Qt5::Test Qt5::DBus)
add_test(NAME fileopstest-filejob COMMAND dbus-run-session ${CMAKE_BINARY_DIR}/bin/fileopstest-filejob)
set_tests_properties(fileopstest-filejob PROPERTIES ENVIRONMENT KDE_FORK_SLAVES=1)
