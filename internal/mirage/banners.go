package mirage

import (
	"crypto/rand"
	"math/big"
)

// Banner database for The Mirage effect
var (
	SSHBanners = []string{
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
		"SSH-2.0-OpenSSH_7.4 Debian-10+deb9u7\r\n",
		"SSH-2.0-OpenSSH_8.0 FreeBSD-20200214\r\n",
		"SSH-2.0-OpenSSH_7.9 CentOS-7.9\r\n",
		"SSH-2.0-OpenSSH_8.1 RedHat-8.1\r\n",
		"SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4\r\n",
		"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n",
		"SSH-2.0-OpenSSH_8.4p1 Arch Linux\r\n",
	}

	HTTPBanners = []string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Debian)\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.20.1\r\n\r\n",
	}

	MySQLBanners = []string{
		"\x0a5.7.35-0ubuntu0.18.04.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x0a8.0.27-0ubuntu0.20.04.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x0a10.3.34-MariaDB-1:10.3.34+maria~focal\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	}

	RedisBanners = []string{
		"$6\r\nRedis\r\n",
		"$7\r\nRedis 6.2.6\r\n",
		"$7\r\nRedis 5.0.7\r\n",
	}

	FTPBanners = []string{
		"220 ProFTPD 1.3.6 Server (ProFTPD Default Installation) [::ffff:192.168.1.1]\r\n",
		"220 (vsFTPd 3.0.3)\r\n",
		"220 Microsoft FTP Service\r\n",
	}

	TelnetBanners = []string{
		"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n\r\n* Documentation:  https://help.ubuntu.com\r\n* Management:     https://landscape.canonical.com\r\n* Support:        https://ubuntu.com/advantage\r\n\r\n  System information as of ",
		"Red Hat Enterprise Linux Server release 7.9 (Maipo)\r\nKernel 3.10.0-1160.el7.x86_64 on an x86_64\r\n\r\nlogin: ",
		"CentOS Linux 7 (Core)\r\nKernel 3.10.0-1160.el7.x86_64 on an x86_64\r\n\r\nlocalhost login: ",
		"Debian GNU/Linux 10\r\n\r\nlocalhost login: ",
	}

	ServiceTypes = []string{"ssh", "http", "mysql", "redis", "ftp", "telnet"}
)

// secureRandomInt returns a secure random integer in [0, max)
func secureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// GetRandomBanner returns a random banner for the given service type
func GetRandomBanner(serviceType string) string {
	switch serviceType {
	case "ssh":
		return SSHBanners[secureRandomInt(len(SSHBanners))]
	case "http":
		return HTTPBanners[secureRandomInt(len(HTTPBanners))]
	case "mysql":
		return MySQLBanners[secureRandomInt(len(MySQLBanners))]
	case "redis":
		return RedisBanners[secureRandomInt(len(RedisBanners))]
	case "ftp":
		return FTPBanners[secureRandomInt(len(FTPBanners))]
	case "telnet":
		return TelnetBanners[secureRandomInt(len(TelnetBanners))]
	default:
		return SSHBanners[secureRandomInt(len(SSHBanners))]
	}
}

// SelectRandomService returns a random service type
func SelectRandomService() string {
	return ServiceTypes[secureRandomInt(len(ServiceTypes))]
}

// SelectServiceByPort selects service type based on port for realistic deception
func SelectServiceByPort(port int) string {
	switch port {
	case 80, 443, 8080, 8443, 8000, 8888:
		return "http"
	case 3306, 5432, 1433, 1521:
		return "mysql"
	case 6379, 11211:
		return "redis"
	case 27017, 27018:
		return "mysql"
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 3389, 5900:
		return "ssh"
	case 9200, 5601:
		return "http"
	case 3000, 5000:
		return "http"
	default:
		return SelectRandomService()
	}
}

