#!/bin/bash
set -e

echo "Building cnetflow_gosnmp for Debian using Docker..."

# Set version variables
VERSION="${VERSION:-1.0.0}"
RELEASE="${RELEASE:-1}"

# Build using Debian Docker container
docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  -e VERSION="$VERSION" \
  -e RELEASE="$RELEASE" \
  debian:13 \
  bash -c '
    set -e

    # Install build dependencies
    apt-get update
    apt-get install -y cmake make golang-go

    # Clean previous build
    rm -rf build
    mkdir build
    cd build

    # Run CMake with Debian-specific settings
    cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DCPACK_GENERATOR=DEB \
      -DCPACK_PACKAGE_VERSION="$VERSION" \
      -DCPACK_DEBIAN_PACKAGE_RELEASE="$RELEASE"

    # Build the Go binary
    make

    # Create DEB package
    cpack -G DEB

    echo "Build complete! DEB package created in build/ directory"
    ls -lh *.deb
  '

# Copy DEB to host
echo ""
echo "DEB packages available in ./build/ directory:"
ls -lh build/*.deb
