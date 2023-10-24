cmake_minimum_required(VERSION 3.16)

project(kio-fuse VERSION 5.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(QT_MIN_VERSION 5.15)
set(KF_MIN_VERSION 5.96)

find_package(ECM ${KF_MIN_VERSION} CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

include(QtVersionOption)
include(ECMSetupVersion)
include(ECMGenerateHeaders)
include(CMakePackageConfigHelpers)
include(FeatureSummary)
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)
include(ECMQtDeclareLoggingCategory)
include(ECMSetupVersion)
include(ECMGenerateDBusServiceFile)
include(ECMConfiguredInstall)

find_package(PkgConfig REQUIRED)
find_package(Qt${QT_MAJOR_VERSION} ${QT_MIN_VERSION} COMPONENTS Core REQUIRED)
find_package(KF${QT_MAJOR_VERSION} ${KF_MIN_VERSION} REQUIRED COMPONENTS
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
target_link_libraries(kio-fuse PRIVATE Qt::Core KF${QT_MAJOR_VERSION}::KIOCore ${FUSE3_LIBRARIES} ${FUSE3_LDFLAGS})
install(TARGETS kio-fuse DESTINATION ${KDE_INSTALL_FULL_LIBEXECDIR})
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	# We could argue that this needs a separate "if(LINUX_WITH_TMPFILES_D)".
	# or a "if(LINUX_WITH_SYSTEMD)".
	install(FILES kio-fuse-tmpfiles.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d)
endif()

ecm_generate_dbus_service_file(
   NAME org.kde.KIOFuse
   EXECUTABLE "${KDE_INSTALL_FULL_LIBEXECDIR}/kio-fuse -f"
   SYSTEMD_SERVICE kio-fuse.service
   DESTINATION ${KDE_INSTALL_DBUSSERVICEDIR}
)

if(DEFINED KDE_INSTALL_SYSTEMDUSERUNITDIR)
	ecm_install_configured_files(INPUT kio-fuse.service.in DESTINATION ${KDE_INSTALL_SYSTEMDUSERUNITDIR})
else()
	ecm_install_configured_files(INPUT kio-fuse.service.in DESTINATION ${SYSTEMD_USER_UNIT_INSTALL_DIR})
endif()

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
