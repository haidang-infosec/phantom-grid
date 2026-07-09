package config

import "fmt"

// PortDefinition represents a port with metadata
type PortDefinition struct {
	Port        int
	Name        string
	Description string
	Category    string
	Alias       string // For generating C macro name
}

// PortCategory groups ports by purpose
const (
	CategoryCore        = "core"
	CategoryDatabase    = "database"
	CategoryAdmin       = "admin"
	CategoryRemote      = "remote"
	CategoryContainer   = "container"
	CategoryApplication = "application"
	CategoryDirectory   = "directory"
	CategoryCache       = "cache"
	CategoryFile        = "file"
	CategoryMessaging   = "messaging"
)

// CriticalPortDefinitions is the single source of truth for protected ports
// This list is used to generate both Go config and eBPF C code
var CriticalPortDefinitions = []PortDefinition{
	// Core Services - Only FTP and SSH are protected
	{21, "FTP", "File Transfer Protocol", CategoryFile, "FTP_PORT"},
	{22, "SSH", "Secure Shell", CategoryCore, "SSH_PORT"},
}

// FakePortDefinitions defines ports for honeypot deception
var FakePortDefinitions = []PortDefinition{
	{80, "HTTP", "HTTP Web Server", CategoryApplication, "HTTP_PORT"},
	{443, "HTTPS", "HTTPS Web Server", CategoryApplication, "HTTPS_PORT"},
	{3306, "MySQL Fake", "MySQL (fake honeypot)", CategoryDatabase, "MYSQL_FAKE_PORT"},
	{5432, "PostgreSQL Fake", "PostgreSQL (fake honeypot)", CategoryDatabase, "POSTGRES_FAKE_PORT"},
	{6379, "Redis Fake", "Redis (fake honeypot)", CategoryDatabase, "REDIS_FAKE_PORT"},
	{27017, "MongoDB Fake", "MongoDB (fake honeypot)", CategoryDatabase, "MONGODB_FAKE_PORT"},
	{8080, "Admin Panel Fake", "Admin Panel (fake)", CategoryAdmin, "ADMIN_PANEL_FAKE_PORT"},
	{8443, "HTTPS Alt Fake", "HTTPS Alternative (fake)", CategoryAdmin, "HTTPS_ALT_FAKE_PORT"},
	{9000, "Admin Panel Fake 2", "Admin Panel (fake)", CategoryAdmin, "ADMIN_PANEL_FAKE_PORT_2"},
	{21, "FTP", "FTP Server", CategoryFile, "FTP_PORT"},
	{23, "Telnet", "Telnet Server", CategoryRemote, "TELNET_PORT"},
	{3389, "RDP Fake", "RDP (fake honeypot)", CategoryRemote, "RDP_FAKE_PORT"},
	{5900, "VNC", "VNC Server", CategoryRemote, "VNC_PORT"},
	{1433, "MSSQL Fake", "MSSQL (fake honeypot)", CategoryDatabase, "MSSQL_FAKE_PORT"},
	{1521, "Oracle Fake", "Oracle (fake honeypot)", CategoryDatabase, "ORACLE_FAKE_PORT"},
	{5433, "PostgreSQL Alt Fake", "PostgreSQL Alternative (fake)", CategoryDatabase, "POSTGRES_ALT_FAKE_PORT"},
	{11211, "Memcached Fake", "Memcached (fake)", CategoryCache, "MEMCACHED_FAKE_PORT"},
	{27018, "MongoDB Shard Fake", "MongoDB Shard (fake)", CategoryDatabase, "MONGODB_SHARD_FAKE_PORT"},
	{9200, "Elasticsearch Fake", "Elasticsearch (fake)", CategoryAdmin, "ELASTICSEARCH_FAKE_PORT"},
	{5601, "Kibana Fake", "Kibana (fake)", CategoryAdmin, "KIBANA_FAKE_PORT"},
	{3000, "Node.js Fake", "Node.js (fake)", CategoryApplication, "NODEJS_FAKE_PORT"},
	{5000, "Flask Fake", "Flask (fake)", CategoryApplication, "FLASK_FAKE_PORT"},
	{8000, "Django Fake", "Django (fake)", CategoryApplication, "DJANGO_FAKE_PORT"},
	{8888, "Jupyter Fake", "Jupyter (fake)", CategoryApplication, "JUPYTER_FAKE_PORT"},
}

// GetCriticalPorts returns list of critical port numbers
func GetCriticalPorts() []int {
	ports := make([]int, len(CriticalPortDefinitions))
	for i, def := range CriticalPortDefinitions {
		ports[i] = def.Port
	}
	return ports
}

// GetFakePorts returns list of fake port numbers
func GetFakePorts() []int {
	ports := make([]int, len(FakePortDefinitions))
	for i, def := range FakePortDefinitions {
		ports[i] = def.Port
	}
	return ports
}

// FindPortDefinition finds a port definition by port number
func FindPortDefinition(port int) *PortDefinition {
	for i := range CriticalPortDefinitions {
		if CriticalPortDefinitions[i].Port == port {
			return &CriticalPortDefinitions[i]
		}
	}
	for i := range FakePortDefinitions {
		if FakePortDefinitions[i].Port == port {
			return &FakePortDefinitions[i]
		}
	}
	return nil
}

// ValidatePorts validates port configuration for consistency
func ValidatePorts() error {
	// Check for duplicates in critical ports
	seen := make(map[int]bool)
	for _, def := range CriticalPortDefinitions {
		if seen[def.Port] {
			return fmt.Errorf("duplicate critical port: %d (%s)", def.Port, def.Name)
		}
		seen[def.Port] = true
	}

	// Check port ranges
	for _, def := range CriticalPortDefinitions {
		if def.Port < 1 || def.Port > 65535 {
			return fmt.Errorf("invalid port range: %d (%s)", def.Port, def.Name)
		}
	}

	return nil
}
