package mesh

import (
	"fmt"
	"strings"
)

// Server is one mesh member as seen from the desktop.
type Server struct {
	Name   string
	MeshIP string
}

// ParseHostsBlock reads the dryserver block of a server's /etc/hosts.
func ParseHostsBlock(hosts string) []Server {
	var out []Server
	in := false
	for _, l := range strings.Split(hosts, "\n") {
		switch strings.TrimSpace(l) {
		case hostsBegin:
			in = true
			continue
		case hostsEnd:
			in = false
			continue
		}
		if f := strings.Fields(l); in && len(f) == 2 {
			out = append(out, Server{Name: f[1], MeshIP: f[0]})
		}
	}
	return out
}

// DesktopSSHConfig renders ~/.ssh/config.d/dryserver: the coordinator by
// its LAN IP, every other server through it (ProxyJump) by mesh IP. The
// agent (your desktop key) is forwarded so you can hop between servers.
func DesktopSSHConfig(user, coordName, coordLanIP, port, knownHosts string, servers []Server) string {
	var b strings.Builder
	portLine := ""
	if port != "" && port != "22" {
		portLine = "    Port " + port + "\n"
	}
	fmt.Fprintf(&b, `# dryserver servers, written by "dryserver ssh-config". Regenerate after
# adding machines. Your key stays on this desktop; it is forwarded (-A).

Host %s
    HostName %s
%s    User %s
    ForwardAgent yes
    UserKnownHostsFile ~/.ssh/known_hosts %s
`, coordName, coordLanIP, portLine, user, knownHosts)
	for _, s := range servers {
		if s.Name == coordName {
			continue
		}
		fmt.Fprintf(&b, `
Host %s
    HostName %s
    User %s
    ProxyJump %s
    ForwardAgent yes
    UserKnownHostsFile ~/.ssh/known_hosts %s
`, s.Name, s.MeshIP, user, coordName, knownHosts)
	}
	return b.String()
}

// DesktopKnownHosts adds the coordinator's LAN address to the key lines from
// a server's /etc/ssh/ssh_known_hosts (name,meshIP keytype key). SSH writes
// addresses on other ports than 22 as [host]:port.
func DesktopKnownHosts(serverKnownHosts, coordName, coordLanIP, port string) string {
	if port != "" && port != "22" {
		coordLanIP = "[" + coordLanIP + "]:" + port
	}
	var b strings.Builder
	b.WriteString("# dryserver server host keys, from the coordinator.\n")
	for _, l := range strings.Split(serverKnownHosts, "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		hosts := f[0]
		if strings.Split(hosts, ",")[0] == coordName {
			hosts += "," + coordLanIP
		}
		fmt.Fprintf(&b, "%s %s %s\n", hosts, f[1], f[2])
	}
	return b.String()
}
