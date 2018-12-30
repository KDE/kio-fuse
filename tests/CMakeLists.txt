set( EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )

find_package(Qt5Test CONFIG REQUIRED)
include(ECMAddTests)

ecm_add_test(fileopstest.cpp
	         TEST_NAME fileopstest
			 LINK_LIBRARIES Qt5::Test)
