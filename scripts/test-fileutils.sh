#!/bin/sh
set -e
export DISTFS_PASSWORD=testpassword
export DISTFS_CONFIG_DIR="/tmp"
# Use the provisioned fuse-user config
CLI="distfs -disable-doh -use-pinentry=false -config /tmp/fuse-user-config.json"

echo "Running FileUtils E2E..."

# 1. touch & stat
echo "Testing touch & stat..."
$CLI touch /users/fuse-user/file1.txt
$CLI stat /users/fuse-user/file1.txt | grep -q "File: file1.txt"

# 2. cp
echo "Testing cp..."
$CLI cp /users/fuse-user/file1.txt /users/fuse-user/file2.txt
$CLI stat /users/fuse-user/file2.txt | grep -q "File: file2.txt"

# 3. mv
echo "Testing mv..."
$CLI mkdir /users/fuse-user/subdir
$CLI mv /users/fuse-user/file2.txt /users/fuse-user/subdir/file3.txt
echo "DEBUG: ls subdir output:"
$CLI ls /users/fuse-user/subdir
$CLI ls /users/fuse-user/subdir | grep -q "file3.txt"

# 4. ln
echo "Testing ln..."
$CLI ln -s /users/fuse-user/file1.txt /users/fuse-user/link1
$CLI stat /users/fuse-user/link1 | grep -q "symbolic link"
$CLI ln /users/fuse-user/file1.txt /users/fuse-user/link2
$CLI stat /users/fuse-user/link2 | grep -q "Links: 2"

# 5. cat, head, tail
echo "Testing cat, head, tail..."
printf "line1\nline2\nline3\n" > /tmp/lines.txt
$CLI put /tmp/lines.txt /users/fuse-user/lines.txt
$CLI cat /users/fuse-user/lines.txt | grep -q "line2"
$CLI head -n 1 /users/fuse-user/lines.txt | grep -q "line1"
$CLI head -n 1 /users/fuse-user/lines.txt | grep -qv "line2"
$CLI tail -n 1 /users/fuse-user/lines.txt | grep -q "line3"

# 6. du, df
echo "Testing du, df..."
$CLI du -h /users/fuse-user
$CLI df -h | grep -q "distfs"

# 7. facl
echo "Testing facl..."
$CLI getfacl /users/fuse-user/file1.txt
# Share with public-user (using registry username)
$CLI setfacl -m u:public-user:r-- /users/fuse-user/file1.txt
$CLI getfacl /users/fuse-user/file1.txt | grep -q "user:.*:r--"

echo "FILEUTILS E2E PASSED"
