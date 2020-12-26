cmake_minimum_required(VERSION 3.1)

project(kio-fuse VERSION 5.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(Qt5_MIN_VERSION 5.12)
# Use ecm_generate_dbus_service_file + ecm_install_configured_files once bumped to 5.73+
set(KF5_MIN_VERSION 5.66)

find_package(ECM ${KF5_MIN_VERSION} CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

include(ECMSetupVersion)
include(ECMGenerateHeaders)
include(CMakePackageConfigHelpers)
include(FeatureSummary)
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDEFrameworkCompilerSettings NO_POLICY_SCOPE)
include(ECMQtDeclareLoggingCategory)
include(ECMSetupVersion)
#include(ECMGenerateDBusServiceFile)
#include(ECMConfiguredInstall)

find_package(PkgConfig REQUIRED)
find_package(Qt5 ${Qt5_MIN_VERSION} COMPONENTS Core REQUIRED)
find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS
	CoreAddons
	KIO
)
pkg_check_modules(FUSE3 REQUIRED fuse3)

if(BUILD_TESTING)
	add_subdirectory(tests)
endif()

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
target_link_libraries(kio-fuse PRIVATE Qt5::Core KF5::KIOCore ${FUSE3_LIBRARIES} ${FUSE3_LDFLAGS})
install(TARGETS kio-fuse DESTINATION ${KDE_INSTALL_FULL_LIBEXECDIR})
install(FILES kio-fuse-tmpfiles.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d)

# Once KF5 5.73 is required
#
#ecm_generate_dbus_service_file(
#   NAME org.kde.KIOFuse
#   EXECUTABLE "${KDE_INSTALL_FULL_LIBEXECDIR}/kio-fuse -f"
#   SYSTEMD_SERVICE kio-fuse.service
#   DESTINATION ${KDE_INSTALL_DBUSSERVICEDIR}
#)
#
#ecm_install_configured_files(INPUT kio-fuse.service.in DESTINATION ${SYSTEMD_USER_UNIT_INSTALL_DIR})

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/org.kde.KIOFuse.service
"[D-BUS Service]
Name=org.kde.KIOFuse
Exec=${KDE_INSTALL_FULL_LIBEXECDIR}/kio-fuse -f
SystemdService=kio-fuse.service
")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.kde.KIOFuse.service DESTINATION ${KDE_INSTALL_DBUSSERVICEDIR})

configure_file(kio-fuse.service.in ${CMAKE_CURRENT_BINARY_DIR}/kio-fuse.service)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kio-fuse.service DESTINATION ${SYSTEMD_USER_UNIT_INSTALL_DIR})

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
