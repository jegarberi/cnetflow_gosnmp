#!/bin/bash
set -e

echo "Building cnetflow_gosnmp for RHEL7..."

# Clean previous build
rm -rf build
mkdir build
cd build

# Run CMake with RHEL7-specific settings
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCPACK_PACKAGE_VERSION="${VERSION:-1.0.0}" \
  -DCPACK_PACKAGE_RELEASE="${RELEASE:-1.el7}"

# Build the Go binary
make

# Create RPM package
make package

echo "Build complete! RPM package created in build/ directory"
ls -lh *.rpm
