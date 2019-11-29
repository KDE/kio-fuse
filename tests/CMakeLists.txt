set( EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )
set(KIOFUSE_TEST_SOURCES
	fileopstest.cpp)

find_package(Qt5Test CONFIG REQUIRED)
find_package(Qt5DBus CONFIG REQUIRED)

qt5_add_dbus_interface(KIOFUSE_TEST_SOURCES org.kde.KIOFuse.VFS.xml kiofuse_interface)

add_executable(fileopstest ${KIOFUSE_TEST_SOURCES})
target_link_libraries(fileopstest PRIVATE Qt5::Test Qt5::DBus)
add_test(NAME fileopstest COMMAND dbus-run-session ${CMAKE_BINARY_DIR}/bin/fileopstest)
set_tests_properties(fileopstest PROPERTIES ENVIRONMENT KDE_FORK_SLAVES=1)
