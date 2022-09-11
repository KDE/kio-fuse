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
