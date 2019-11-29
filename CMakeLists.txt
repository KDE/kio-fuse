cmake_minimum_required(VERSION 3.1)

project(kio-fuse VERSION 0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(Qt5_MIN_VERSION 5.9)
set(KF5_MIN_VERSION 5.52)

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

find_package(PkgConfig REQUIRED)
find_package(Qt5 ${Qt5_MIN_VERSION} COMPONENTS Core REQUIRED)
find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS
	KIO
	DBusAddons
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

ecm_qt_declare_logging_category(KIOFUSE_SOURCES
	HEADER debug.h
	IDENTIFIER KIOFUSE_LOG
	CATEGORY_NAME org.kde.kio.fuse
	DEFAULT_SEVERITY Warning)

add_executable(kio-fuse ${KIOFUSE_SOURCES})
target_include_directories(kio-fuse PRIVATE ${FUSE3_INCLUDE_DIRS})
target_compile_definitions(kio-fuse PRIVATE FUSE_USE_VERSION=31 ${FUSE3_CFLAGS_OTHER})
target_link_libraries(kio-fuse PRIVATE Qt5::Core KF5::KIOCore ${FUSE3_LIBRARIES})
install(TARGETS kio-fuse DESTINATION ${KDE_INSTALL_FULL_LIBEXECDIR})
install(FILES kio-fuse-tmpfiles.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d)
kdbusaddons_generate_dbus_service_file(kio-fuse org.kde.KIOFuse ${KDE_INSTALL_FULL_LIBEXECDIR})

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
