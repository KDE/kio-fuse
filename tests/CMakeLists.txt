set( EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )
set(KIOFUSE_TEST_SOURCES
	fileopstest.cpp)

find_package(Qt${QT_MAJOR_VERSION}Test CONFIG REQUIRED)
find_package(Qt${QT_MAJOR_VERSION}DBus CONFIG REQUIRED)

qt_add_dbus_interface(KIOFUSE_TEST_SOURCES org.kde.KIOFuse.VFS.xml kiofuse_interface)
qt_add_dbus_interface(KIOFUSE_TEST_SOURCES org.kde.KIOFuse.Private.xml kiofuseprivate_interface)

add_executable(fileopstest-cache ${KIOFUSE_TEST_SOURCES})
target_link_libraries(fileopstest-cache PRIVATE Qt::Test Qt::DBus KF${QT_MAJOR_VERSION}::KIOCore)
target_compile_definitions(fileopstest-cache PRIVATE -DTEST_CACHE_BASED_IO)
add_test(NAME fileopstest-cache COMMAND dbus-run-session ${CMAKE_BINARY_DIR}/bin/fileopstest-cache)

add_executable(fileopstest-filejob ${KIOFUSE_TEST_SOURCES})
target_link_libraries(fileopstest-filejob PRIVATE Qt::Test Qt::DBus KF${QT_MAJOR_VERSION}::KIOCore)
add_test(NAME fileopstest-filejob COMMAND dbus-run-session ${CMAKE_BINARY_DIR}/bin/fileopstest-filejob)
