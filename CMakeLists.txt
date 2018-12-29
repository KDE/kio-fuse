cmake_minimum_required(VERSION 3.1)

project(kio-fuse VERSION 0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
find_package(Qt5 COMPONENTS Core REQUIRED)
find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS KIO)
pkg_check_modules(FUSE3 REQUIRED fuse3)

set(KIOFUSE_SOURCES
	main.cpp
	kiofusevfs.cpp
	kiofusevfs.h
	kiofusenode.cpp
	kiofusenode.h)

add_executable(kio-fuse ${KIOFUSE_SOURCES})
target_include_directories(kio-fuse PRIVATE ${FUSE3_INCLUDE_DIRS})
target_compile_definitions(kio-fuse PRIVATE FUSE_USE_VERSION=31 ${FUSE3_CFLAGS_OTHER})
target_link_libraries(kio-fuse PRIVATE Qt5::Core KF5::KIOCore ${FUSE3_LIBRARIES})

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
