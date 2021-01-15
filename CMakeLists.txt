cmake_minimum_required(VERSION 3.1.0)

project(web-eid VERSION 21.01)

if(NOT DEFINED ENV{QTDIR})
	message(FATAL_ERROR "QTDIR environment variable is not set!")
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_PREFIX_PATH $ENV{QTDIR}/lib/cmake)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(INSTALL_BIN_PATH bin)

find_package(Qt5 REQUIRED COMPONENTS Core Widgets WebSockets Concurrent Svg)

file(GLOB web-eid_SRCS src/*.cpp src/dialogs/*.h)
set(web-eid_RESOURCES src/web-eid.qrc src/translations/strings.qrc)

if (APPLE)
	find_library(PCSC PCSC)
	find_library(ServiceManagement ServiceManagement)
	find_library(CoreFoundation CoreFoundation)
	find_library(AppKit AppKit)

	set (web-eid_SRCS src/dialogs/macosxui.mm ${web-eid_SRCS})
	set(LIBS ${CoreFoundation} ${PCSC} ${ServiceManagement} ${AppKit} dl)
endif (APPLE)

foreach(plugin ${Qt5Network_PLUGINS})
  get_target_property(_loc ${plugin} LOCATION)
  message("Plugin ${plugin} is at location ${_loc}")
endforeach()

include_directories(src src/dialogs)

add_definitions(-DVERSION="${PROJECT_VERSION}-evidos")
add_definitions(-DGIT_REVISION="")

add_executable(web-eid WIN32 MACOSX_BUNDLE ${web-eid_SRCS} ${web-eid_RESOURCES})
if(MSVC)
    target_compile_definitions(web-eid PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    target_link_libraries(web-eid winscard ncrypt crypt32 cryptui Advapi32)
endif ()

install(TARGETS web-eid DESTINATION ${INSTALL_BIN_PATH})

target_link_libraries(web-eid
	Qt5::Widgets
	Qt5::Svg
	Qt5::Network
	Qt5::WebSockets
	Qt5::Concurrent
	${LIBS})

set(CPACK_PACKAGE_EXECUTABLES web-eid "Web eID for Windows")
set(CPACK_PACKAGE_VENDOR "Evidos")
set(CPACK_PACKAGE_DESCRIPTION "Web eID is the platform that makes your traditional eID work well on the Web.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/Evidos/web-eid")

IF (WIN32)
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "LICENSE.txt" COPYONLY)
	
	set(CPACK_GENERATOR WIX)
	set(CPACK_WIX_UPGRADE_GUID "79730a31-61d7-4395-b91e-191279b08798")
	set(CPACK_RESOURCE_FILE_LICENSE "LICENSE.txt")
	#SET(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cpack.wixpatch")
	SET(CPACK_WIX_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/wix.template.in")
	SET(CPACK_WIX_EXTENSIONS "WixUtilExtension")
	
	if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wix-banner.bmp")
		set(CPACK_WIX_UI_BANNER "${CMAKE_CURRENT_SOURCE_DIR}/wix-banner.bmp")
	endif()
	
	if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wix-dialog.bmp")
		set(CPACK_WIX_UI_DIALOG "${CMAKE_CURRENT_SOURCE_DIR}/wix-dialog.bmp")
	endif()
	
	include(DeployQt)
	windeployqt(web-eid ${INSTALL_BIN_PATH})
endif (WIN32)


if(APPLE)
	include(DeployQt)
	macdeployqt(web-eid ${INSTALL_BIN_PATH})
endif()

include(CPack)
