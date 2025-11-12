cmake_minimum_required(VERSION 3.10)
project(cnetflow_gosnmp VERSION 1.0.0)

# Set Go compiler
find_program(GO_EXECUTABLE go REQUIRED)

# Project variables
set(PROJECT_NAME "cnetflow_gosnmp")
set(GO_MODULE "github.com/jegarberi/cnetflow_gosnmp")
set(BINARY_NAME "${PROJECT_NAME}")
set(GO_SOURCE_FILE "${CMAKE_SOURCE_DIR}/cnetflow_gosnmp.go")

# Build flags for static linking (important for CentOS 7)
set(GO_BUILD_FLAGS "-ldflags=-linkmode external -extldflags '-static' -s -w")

# Custom target to build the Go binary
add_custom_target(${PROJECT_NAME} ALL
    COMMAND ${GO_EXECUTABLE} mod download
    COMMAND CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ${GO_EXECUTABLE} build
        "-ldflags=-s -w"
        -o ${CMAKE_BINARY_DIR}/${BINARY_NAME}
        ${GO_SOURCE_FILE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building Go binary ${BINARY_NAME}"
    BYPRODUCTS ${CMAKE_BINARY_DIR}/${BINARY_NAME}
)

# Install the binary
install(PROGRAMS ${CMAKE_BINARY_DIR}/${BINARY_NAME}
    DESTINATION bin
)

# Install systemd service file if it exists
if(EXISTS "${CMAKE_SOURCE_DIR}/${PROJECT_NAME}.service")
    install(FILES ${CMAKE_SOURCE_DIR}/${PROJECT_NAME}.service
        DESTINATION /usr/lib/systemd/system
    )
endif()

# Install environment file if needed
if(EXISTS "${CMAKE_SOURCE_DIR}/.env.example")
    install(FILES ${CMAKE_SOURCE_DIR}/.env.example
        DESTINATION /etc/${PROJECT_NAME}
        RENAME config.env
    )
endif()

# CPack configuration for RPM packaging
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "jegarberi@example.com")
set(CPACK_PACKAGE_VENDOR "cnetflow")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SNMP polling service for cnetflow")
set(CPACK_PACKAGE_DESCRIPTION "A Go-based SNMP polling service that collects network interface metrics and stores them in PostgreSQL.")

# RPM specific settings
set(CPACK_RPM_PACKAGE_LICENSE "Proprietary")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_PACKAGE_REQUIRES "postgresql-libs >= 9.2")
set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    /usr/bin
    /usr/lib/systemd
    /usr/lib/systemd/system
    /etc
)

# Post-install script
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/rpm-post-install.sh")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/rpm-pre-uninstall.sh")

include(CPack)
