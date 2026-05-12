set( EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )
set(KIOFUSE_TEST_SOURCES
	fileopstest.cpp)

find_package(Qt${QT_MAJOR_VERSION}Test CONFIG REQUIRED)
find_package(Qt${QT_MAJOR_VERSION}DBus CONFIG REQUIRED)

qt_add_dbus_interface(KIOFUSE_TEST_SOURCES org.kde.KIOFuse.VFS.xml kiofuse_interface)
qt_add_dbus_interface(KIOFUSE_TEST_SOURCES org.kde.KIOFuse.Private.xml kiofuseprivate_interface)

set(KIOFUSE_STUBWORKER_DIR ${CMAKE_CURRENT_BINARY_DIR}/plugins)
add_library(kio_stub MODULE stubworker.cpp)
set_target_properties(kio_stub PROPERTIES
	LIBRARY_OUTPUT_DIRECTORY ${KIOFUSE_STUBWORKER_DIR}/kf${QT_MAJOR_VERSION}/kio
	OUTPUT_NAME "stub"
)
target_link_libraries(kio_stub PRIVATE KF${QT_MAJOR_VERSION}::KIOCore)

add_executable(fileopstest-cache ${KIOFUSE_TEST_SOURCES})
target_link_libraries(fileopstest-cache PRIVATE Qt::Test Qt::DBus KF${QT_MAJOR_VERSION}::KIOCore)
target_compile_definitions(fileopstest-cache PRIVATE -DTEST_CACHE_BASED_IO
	"KIOFUSE_STUBWORKER_DIR=\"${KIOFUSE_STUBWORKER_DIR}\"")
add_dependencies(fileopstest-cache kio_stub)
add_test(NAME fileopstest-cache COMMAND dbus-run-session ${CMAKE_BINARY_DIR}/bin/fileopstest-cache)

add_executable(fileopstest-filejob ${KIOFUSE_TEST_SOURCES})
target_link_libraries(fileopstest-filejob PRIVATE Qt::Test Qt::DBus KF${QT_MAJOR_VERSION}::KIOCore)
target_compile_definitions(fileopstest-filejob PRIVATE
	"KIOFUSE_STUBWORKER_DIR=\"${KIOFUSE_STUBWORKER_DIR}\"")
add_dependencies(fileopstest-filejob kio_stub)
add_test(NAME fileopstest-filejob COMMAND dbus-run-session ${CMAKE_BINARY_DIR}/bin/fileopstest-filejob)
