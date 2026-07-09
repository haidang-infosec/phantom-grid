package honeypot

import (
	"fmt"
	"strings"
)

// VirtualFileSystem represents a fake file system for honeypot
type VirtualFileSystem struct {
	files map[string]string
	dirs  map[string][]string
}

// NewVirtualFileSystem creates a new virtual file system
func NewVirtualFileSystem() *VirtualFileSystem {
	vfs := &VirtualFileSystem{
		files: make(map[string]string),
		dirs:  make(map[string][]string),
	}
	vfs.init()
	return vfs
}

func (vfs *VirtualFileSystem) init() {
	// Root directory structure
	vfs.dirs["/"] = []string{"root", "home", "etc", "var", "tmp", "usr", "opt", "boot"}
	vfs.dirs["/root"] = []string{".bashrc", ".bash_history", ".ssh", "backup.tar.gz", "config.txt", "logs"}
	vfs.dirs["/home"] = []string{"user", "admin", "www"}
	vfs.dirs["/etc"] = []string{"passwd", "shadow", "hosts", "nginx", "apache2", "mysql"}
	vfs.dirs["/var"] = []string{"log", "www", "backup", "tmp"}
	vfs.dirs["/var/log"] = []string{"auth.log", "syslog", "nginx", "apache2"}
	vfs.dirs["/var/www"] = []string{"html", "uploads", "config.php"}
	vfs.dirs["/tmp"] = []string{"session.tmp", "cache.tmp"}

	// File contents
	vfs.files["/etc/passwd"] = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
tcpdump:x:109:114::/nonexistent:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
landscape:x:111:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:112:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
`

	vfs.files["/etc/hosts"] = `127.0.0.1	localhost
127.0.1.1	server
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
`

	vfs.files["/var/log/auth.log"] = `Dec 15 10:23:15 server sshd[1234]: Accepted publickey for root from 192.168.1.100 port 54321 ssh2
Dec 15 10:25:30 server sshd[1235]: Failed password for invalid user admin from 192.168.1.101 port 54322 ssh2
Dec 15 10:26:45 server sshd[1236]: Accepted publickey for ubuntu from 192.168.1.102 port 54323 ssh2
Dec 15 10:28:12 server sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update
Dec 15 10:30:22 server sshd[1237]: Invalid user test from 192.168.1.103 port 54324 ssh2
`

	vfs.files["/var/log/syslog"] = `Dec 15 10:20:01 server systemd[1]: Started Daily apt upgrade and clean activities.
Dec 15 10:20:15 server systemd[1]: Starting Cleanup of Temporary Directories...
Dec 15 10:20:15 server systemd[1]: Started Cleanup of Temporary Directories.
Dec 15 10:23:15 server sshd[1234]: Server listening on 0.0.0.0 port 22.
Dec 15 10:23:15 server sshd[1234]: Server listening on :: port 22.
Dec 15 10:25:30 server kernel: [12345.678901] audit: type=1106 audit(1639561530.123:456): pid=1235 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct="admin" exe="/usr/sbin/sshd" hostname=? addr=192.168.1.101 terminal=ssh res=failed'
`

	vfs.files["/root/.bash_history"] = `cd /var/www
ls -la
cat config.php
mysql -u root -p
exit
`

	vfs.files["/root/config.txt"] = `# Database Configuration
DB_HOST=localhost
DB_USER=admin
DB_PASS=********
DB_NAME=production

# API Keys
API_KEY=sk_live_51H3ll0W0rld
SECRET_KEY=sk_test_4BcDeFgHiJkLmNoPqRsTuVwXyZ
`

	vfs.files["/var/www/config.php"] = `<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'admin');
define('DB_PASS', 'P@ssw0rd123');
define('DB_NAME', 'wordpress');
define('WP_DEBUG', false);
?>`

	vfs.files["/etc/nginx/nginx.conf"] = `user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
	worker_connections 768;
}

http {
	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	server {
		listen 80 default_server;
		listen [::]:80 default_server;
		root /var/www/html;
		index index.html index.htm index.nginx-debian.html;
		server_name _;
		location / {
			try_files $uri $uri/ =404;
		}
	}
}
`
}

// ListFiles returns file listing for a directory
func (vfs *VirtualFileSystem) ListFiles(path string) string {
	path = vfs.normalizePath(path)

	if files, ok := vfs.dirs[path]; ok {
		output := fmt.Sprintf("total %d\r\n", len(files))
		for _, file := range files {
			// Simulate file permissions and sizes
			if strings.HasPrefix(file, ".") {
				output += fmt.Sprintf("-rw-r--r-- 1 root root  1024 Dec 15 10:23 %s\r\n", file)
			} else if strings.Contains(file, ".") {
				output += fmt.Sprintf("-rw-r--r-- 1 root root  2048 Dec 15 10:23 %s\r\n", file)
			} else {
				output += fmt.Sprintf("drwxr-xr-x 2 root root  4096 Dec 15 10:23 %s\r\n", file)
			}
		}
		return output
	}
	return fmt.Sprintf("ls: cannot access '%s': No such file or directory\r\n", path)
}

// ReadFile returns file content
func (vfs *VirtualFileSystem) ReadFile(path string) (string, bool) {
	path = vfs.normalizePath(path)
	content, ok := vfs.files[path]
	return content, ok
}

// FileExists checks if file exists
func (vfs *VirtualFileSystem) FileExists(path string) bool {
	path = vfs.normalizePath(path)
	_, exists := vfs.files[path]
	if !exists {
		_, exists = vfs.dirs[path]
	}
	return exists
}

// normalizePath normalizes file path
func (vfs *VirtualFileSystem) normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "." {
		return "/root"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/root/" + path
	}
	return path
}
