set( EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )
set(KIOFUSE_SOURCES
	main.cpp
	kiofusevfs.cpp
	kiofusevfs.h
	kiofuseservice.cpp
	kiofuseservice.h
	kiofusenode.h)

ecm_setup_version(PROJECT
	VARIABLE_PREFIX KIOFUSE
	VERSION_HEADER kiofuseversion.h)

ecm_qt_declare_logging_category(KIOFUSE_SOURCES
	HEADER debug.h
	IDENTIFIER KIOFUSE_LOG
	CATEGORY_NAME org.kde.kio.fuse
	DEFAULT_SEVERITY Warning)

add_executable(kio-fuse ${KIOFUSE_SOURCES})
target_include_directories(kio-fuse PRIVATE ${FUSE3_INCLUDE_DIRS})
target_compile_definitions(kio-fuse PRIVATE FUSE_USE_VERSION=31 ${FUSE3_CFLAGS_OTHER})
target_link_libraries(kio-fuse PRIVATE Qt::Core KF${QT_MAJOR_VERSION}::KIOCore ${FUSE3_LIBRARIES} ${FUSE3_LDFLAGS})
install(TARGETS kio-fuse DESTINATION ${KDE_INSTALL_FULL_LIBEXECDIR})
