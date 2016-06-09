package main

import (
	"fmt"
	"strings"
	"bufio"
	"os"
	"errors"
	"os/exec"
	"regexp"
	"net"

	"github.com/gin-gonic/gin"
	"gopkg.in/alecthomas/kingpin.v2"
	log "github.com/Sirupsen/logrus"
)

const (
	ver string = "0.20"
)

var (
	openvpnStatusFileList = StatusFileList(kingpin.Arg("openvpn status files", "openvpn status file list"))
	openvpnProto = kingpin.Flag("openvpn-proto", "openvpn tunnel protocol").Default("tcp-udp").Short('p').String()
	openvpnPort = kingpin.Flag("openvpn-port", "openvpn tunnel port").Default("1194").Short('r').String()
	bindPort = kingpin.Flag("bind-port", "port to bind daemon to").Default("8888").Short('t').String()
	bindAddr = kingpin.Flag("bind-addr", "address to bind daemon to").Default("127.0.0.1").Short('a').String()
	logFile = kingpin.Flag("log-file", "log file").Default("/var/log/openvpn-collision-manager.log").Short('l').String()
)

type statusFileList []string

func (i *statusFileList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func (i *statusFileList) String() string {
	return ""
}

func (i *statusFileList	) IsCumulative() bool {
	return true
}

func StatusFileList(s kingpin.Settings) (target *[]string) {
	target = new([]string)
	s.SetValue((*statusFileList)(target))
	return
}

type BlockIp struct {
	Username string `json:"username" binding:"required"`
	Ip string `json:"ip" binding:"required"`
}

func getOpenvpnStatus(filename string) (map[string]map[string]string, error) {
	openvpnStatus := make(map[string]map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Cannot open openvpn status file %s", filename))
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		user := strings.Split(scanner.Text(), ",")
		// parse only CLIENT LIST lines, not ROUTING TABLE
		if len(user) == 5 {
			var revdns string = ""
			ip := strings.Split(user[1], ":")[0]

			rev, err := net.LookupAddr(ip)
			if err == nil {
				revdns = rev[0]
			} 
			openvpnStatus[user[0]] = map[string]string{
				"username": user[0],
				"remote_ip": ip,
				"remote_revdns": revdns,
				"bytes_recv": user[2],
				"bytes_sent": user[3],
				"connected_since": user[4],
				"source_status_file": filename,
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.New(fmt.Sprintf("Cannot parse openvpn status file %s", filename))
	}
	return openvpnStatus, nil
}

func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func stringInMapValue(a string, list []map[string]string) bool {
	for _, item := range list {
		for k, _ := range item {
			if k == a {
				return true
			}
		}
	}
    return false
}

func getIptablesData() (map[string][]map[string]string, error) {
	iptablesData := make([]map[string]string, 0)

	cmd, err := exec.Command("iptables", "-nL", "INPUT").Output()
	if err != nil {
		return nil, errors.New("Cannot gather iptables output")
	}

	lines := strings.Split(string(cmd), "\n")

	// DROP       tcp  --  1.1.1.1              0.0.0.0/0            tcp dpt:1194 STRING match  "test@wikia-inc.com" ALGO name bm TO 65535 /* test@wikia-inc.com */
	r := regexp.MustCompile(`\w+\s+\w+\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+/\*\s(.+)\s\*/`)
	for _, line := range lines {
		if matches := r.FindStringSubmatch(line); matches != nil {
			iptablesData = append(iptablesData, map[string]string{matches[2]: matches[1]})
		}
	}

	iptablesDataMap := make(map[string][]map[string]string)
	for _, entry := range iptablesData {
		for key, value := range entry {
			// do not append duplicates
			if !stringInMapValue(value, iptablesDataMap[key]) {
				a := make(map[string]string)
				rev, err := net.LookupAddr(value)
				if err == nil {
					a[value] = rev[0]
				} else {
					a[value] = ""				
				}
				iptablesDataMap[key] = append(iptablesDataMap[key], a)
			}
		}
	}

	return iptablesDataMap, nil
}

func addIptablesRule(ip, username, proto string) error {
	cmdName := "iptables"
	cmdArgs := []string{
		"-A",
		"INPUT",
		"-s",
		ip,
		"-p",
		proto,
		"--dport",
		*openvpnPort,
		"-m",
		"string",
		"--string",
		username,
		"--algo",
		"bm",
		"-m",
		"comment",
		"--comment",
		username,
		"-j",
		"DROP",
	}

	return executeShell(cmdName, cmdArgs)
}

func deleteIptablesRule(ip, username, proto string) bool {
	cmdName := "iptables"
	cmdArgs := []string{
		"-D",
		"INPUT",
		"-s",
		ip,
		"-p",
		proto,
		"--dport",
		*openvpnPort,
		"-m",
		"string",
		"--string",
		username,
		"--algo",
		"bm",
		"-m",
		"comment",
		"--comment",
		username,
		"-j",
		"DROP",
	}

	var success bool = false
	for {
		err := executeShell(cmdName, cmdArgs)
		if err == nil {
			success = true
		} else {
			break
		}
	}
	return success
}

func executeShell(cmdName string, cmdArgs []string) error {
	if err := exec.Command(cmdName, cmdArgs...).Run(); err == nil {
		log.Debugf("Executing shell command success: %s %s", cmdName, strings.Join(cmdArgs, " "))
		return nil
	} else {
		log.Debugf("Executing shell command failed: %s %s: %s", cmdName, strings.Join(cmdArgs, " "), err)
		return errors.New(fmt.Sprintf("Cannot execute shell command: %s %s: %s", cmdName, strings.Join(cmdArgs, " "), err))
	}
}

func getUserData(c *gin.Context) {
	username := c.Param("username")

	log.Infof("Getting data for user %s", username)

	result := make(gin.H)

	ovpnStatus := make(map[string]map[string]string)
	for _, statusFile := range *openvpnStatusFileList {
		status, err := getOpenvpnStatus(statusFile)
		if err == nil {
			for k, v := range status {
				ovpnStatus[k] = v
			}
		} else {
			c.JSON(500, gin.H{"error": fmt.Sprintf("cannot get data from openvpn status file %s: %s", statusFile, err)})
			return
		}
	}

	if value, ok := ovpnStatus[username]; ok {
		result["username"] = username
		result["status"] = "connected"
		result["remote_ip"] = value["remote_ip"]
		result["remote_revdns"] = value["remote_revdns"]
		result["bytes_recv"] = value["bytes_recv"]
		result["bytes_sent"] = value["bytes_sent"]
		result["connected_since"] = value["connected_since"]
		result["source_status_file"] = value["source_status_file"]
	} else {
		result["username"] = username
		result["status"] = "disconnected"
	}

	iptablesData, err := getIptablesData()
	if err != nil {
		log.Errorf("Cannot get iptables data: %s", err)
	}

	if value, ok := iptablesData[username]; ok {
		result["blocked_ip"] = value
	} else {
		result["blocked_ip"] = []string{}
	}

	c.JSON(200, result)
}

func blockIp(c *gin.Context) {
	var json BlockIp
	var username, ip string

	if c.BindJSON(&json) == nil {
		username = json.Username
		ip = json.Ip
	}

	if username == "" || ip == "" {
		c.JSON(500, gin.H{"error": "username or ip empty"})
		return
	}

	log.Infof("Blocking IP %s for %s", ip, username)

	iptablesData, err := getIptablesData()
	if err != nil {
		c.JSON(500, gin.H{"error": "cannot get iptables data"})
		return
	}
	
	if stringInMapValue(ip, iptablesData[username]) {
		log.Infof("IP %s already blocked for %s", ip, username)
		c.JSON(200, gin.H{"status": "ok"})
		return
	}

	var success bool = false
	if *openvpnProto == "tcp-udp" {
		var fail bool = false
		for _, proto := range []string{"tcp", "udp"} {
			err = addIptablesRule(ip, username, proto)
			if err != nil {
				log.Warningf("Cannot add iptables rule with IP %s, protocol %s for user %s", ip, proto, username)
				fail = true
			}
		}
		if !fail {
			success = true
		}
	} else if *openvpnProto == "tcp" || *openvpnProto == "udp" {
		err = addIptablesRule(ip, username, *openvpnProto)
		if err == nil {
			success = true
		} else {
			log.Warningf("Cannot add iptables rule with IP %s, protocol %s for user %s", ip, *openvpnProto, username)
		}
	}

	if success {
		c.JSON(200, gin.H{"status": "ok"})
	} else {
		c.JSON(500, gin.H{"status": "failed"})
	}
}

func unblockIp (c *gin.Context) {
	var json BlockIp
	var username, ip string
	if c.BindJSON(&json) == nil {
		username = json.Username
		ip = json.Ip
	}

	if username == "" || ip == "" {
		c.JSON(500, gin.H{"error": "username or ip empty"})
		return
	}

	log.Infof("Unblocking IP %s for %s", ip, username)

	var success bool = false
	if *openvpnProto == "tcp-udp" {
		var fail bool = false
		for _, proto := range []string{"tcp", "udp"} {
			if !deleteIptablesRule(ip, username, proto) {
				log.Warningf("Cannot delete iptables rule with IP %s, protocol %s for user %s", ip, proto, username)
				fail = true
			}
		}
		if !fail {
			success = true
		}
	} else if *openvpnProto == "tcp" || *openvpnProto == "udp" {
		if deleteIptablesRule(ip, username, *openvpnProto) {
			success = true
		} else {
			log.Warningf("Cannot delete iptables rule with IP %s, protocol %s for user %s", ip, *openvpnProto, username)
		}
	}

	if success {
		c.JSON(200, gin.H{"status": "ok"})
	} else {
		c.JSON(500, gin.H{"status": "failed"})
	}
}

func main() {
	kingpin.Version(ver)
	kingpin.Parse()

	if *openvpnProto != "tcp-udp" && *openvpnProto != "tcp" && *openvpnProto != "udp" {
		kingpin.FatalUsage("possible protocol variants: tcp, udp, tcp-udp")
	}

	if len(*openvpnStatusFileList) == 0 {
		kingpin.FatalUsage("no openvpn status file provided")
	}

	f, err := os.OpenFile(*logFile, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0644)
	if err != nil {
	    panic(err)
	}
	defer f.Close()
	log.SetOutput(f)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{DisableColors: true})

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.GET("/users/:username", getUserData)
	r.POST("/blockip", blockIp)
	r.POST("/unblockip", unblockIp)

	r.Run(*bindAddr + ":" + *bindPort)
}
