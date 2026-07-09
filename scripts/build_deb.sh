#!/bin/bash
set -e

VERSION="1.0.0"
PKG_NAME="phantom-grid"
ARCH="amd64"
DEB_DIR="build/deb_${PKG_NAME}_${VERSION}_${ARCH}"

echo "Building Debian Package for ${PKG_NAME} v${VERSION}..."

# Create directory structure
mkdir -p ${DEB_DIR}/DEBIAN
mkdir -p ${DEB_DIR}/usr/local/bin
mkdir -p ${DEB_DIR}/etc/systemd/system
mkdir -p ${DEB_DIR}/etc/phantom

# Create control file
cat <<EOF > ${DEB_DIR}/DEBIAN/control
Package: phantom-grid
Version: ${VERSION}
Section: security
Priority: optional
Architecture: ${ARCH}
Depends: libbpf1 (>= 0.5.0)
Maintainer: Phantom Grid Team <team@phantomgrid.io>
Description: Phantom Grid - Zero Trust eBPF SPA System
 An advanced Active Defense system utilizing eBPF and Single Packet Authorization
 to protect Linux servers against DDoS and network scans.
EOF

# Create postinst script (executed after installation)
cat <<EOF > ${DEB_DIR}/DEBIAN/postinst
#!/bin/bash
systemctl daemon-reload
echo "Phantom Grid installed. To enable and start services:"
echo "  systemctl enable --now phantom-agent"
echo "  systemctl enable --now phantom-fleet"
EOF
chmod 755 ${DEB_DIR}/DEBIAN/postinst

# Copy binaries
if [ ! -f "bin/phantom-grid" ] || [ ! -f "bin/fleet" ]; then
    echo "Binaries not found. Please run 'make build' first."
    exit 1
fi

cp bin/phantom-grid ${DEB_DIR}/usr/local/bin/
cp bin/fleet ${DEB_DIR}/usr/local/bin/
cp bin/spa-client ${DEB_DIR}/usr/local/bin/

chmod 755 ${DEB_DIR}/usr/local/bin/*

# Copy systemd services
cp scripts/systemd/phantom-agent.service ${DEB_DIR}/etc/systemd/system/
cp scripts/systemd/phantom-fleet.service ${DEB_DIR}/etc/systemd/system/

# Build the .deb
dpkg-deb --build ${DEB_DIR}

rm -rf ${DEB_DIR}

echo "Package created at ${DEB_DIR}.deb"
