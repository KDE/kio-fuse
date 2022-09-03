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

add_compile_options(
    "-Wall" "-Wextra" "-Wfloat-equal" "-Wundef" "-Wshadow" "-Wpointer-arith"
    "-Wcast-align" "-fsanitize=address" 
    "$<$<CONFIG:DEBUG>:-O0;-g;-DDEBUG;-Werror;-fsanitize=address;-fno-omit-frame-pointer>"
)
add_link_options(
    "$<$<CONFIG:DEBUG>:-fsanitize=address;>"
)
add_executable(kio-fuse ${KIOFUSE_SOURCES})
#-Wstrict-prototypes -Wstrict-overflow=5 \
#2                  -Wwrite-strings -Waggregate-return -Wcast-qual \
#  3                  -Wswitch-default -Wswitch-enum -Wconversion -Wunreachable-code \
#  4                  -Wformat=2 -pedantic -std=c17
target_include_directories(kio-fuse PRIVATE ${FUSE3_INCLUDE_DIRS})
target_compile_definitions(kio-fuse PRIVATE FUSE_USE_VERSION=31 ${FUSE3_CFLAGS_OTHER})
target_link_libraries(kio-fuse PRIVATE Qt::Core KF${QT_MAJOR_VERSION}::KIOCore ${FUSE3_LIBRARIES} ${FUSE3_LDFLAGS})
install(TARGETS kio-fuse DESTINATION ${KDE_INSTALL_FULL_LIBEXECDIR})
