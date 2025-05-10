cmake_minimum_required(VERSION 3.16)

project(kio-fuse VERSION 5.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(QT_MIN_VERSION 6.8)
set(KF_MIN_VERSION 6.0)

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

add_subdirectory(src)
add_subdirectory(data)
if(BUILD_TESTING)
	add_subdirectory(tests)
endif()

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
