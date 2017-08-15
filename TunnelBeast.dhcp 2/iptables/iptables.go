package iptables

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
)

//var INTERFACE = "tun0"
var defaultRouteIface = "eth0"

func Init(Interface string) error {
	log.Println("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1")
	err := exec.Command("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	if err != nil {
		return err
	}
	log.Println("sudo", "iptables", "-t", "nat", "--flush")
	err = exec.Command("sudo", "iptables", "-t", "nat", "--flush").Run()
	if err != nil {
		return err
	}
	log.Println("sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", Interface, "-j", "MASQUERADE")
	err = exec.Command("sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", Interface, "-j", "MASQUERADE").Run()
	if err != nil {
		return err
	}
	log.Println("adding routing table Restful api")
	log.Println("route add -net 192.168.1.240 gw 10.8.0.5 netmask 255.255.255.255 dev tun0")
	err = exec.Command("sudo", "route", "add", "-net", "192.168.1.240", "gw", "10.8.0.5", "netmask", "255.255.255.255", "dev", "tun0").Run()
	log.Println("err is", err)

	return nil
}

func GetIpFromVif(vifname string) [2]string {
	var ipmask [2]string
	out, err := exec.Command("ifconfig", vifname).Output()
	if err != nil {
		log.Fatal(err)
	}
	if bytes.Contains(out, []byte("inet addr:")) {
		//s := bytes.Split(out, []byte("  "))
		s := bytes.Fields(out)
		//fmt.Println("s is ", s)
		//str := fmt.Sprintf("%s", s)
		//fmt.Println("str", str)
		ipaddr := s[6]
		mask := s[8]
		fmt.Println("ipaddr", string(ipaddr))
		fmt.Println("mask", string(mask))
		iptmp := bytes.Split(ipaddr, []byte(":"))[1]
		masktmp := bytes.Split(mask, []byte(":"))[1]
		ipmask[0] = string(iptmp)
		ipmask[1] = string(masktmp)
		fmt.Println("ipmask[0]", ipmask[0])
		fmt.Println("ipmask[1]", ipmask[1])

	} else {
		log.Println("no virtual interface")
	}
	return ipmask
}

func DeleteDuplicateRoute(localinterface string, vifName string) error {
	out, err := exec.Command("ip", "route", "show").Output()
	if err != nil {
		log.Fatal(err)
	}

	if bytes.Contains(out, []byte(vifName)) {
		s := bytes.Fields(out)
		//fmt.Println("s is ", s)
		str := fmt.Sprintf("%s", s)
		fmt.Println("str", str)
		gateway := string(s[7])
		log.Println("gateway is ", gateway)
		log.Println("vifName is ", vifName)
		log.Println("route del -net 202.50.209.23 gw", gateway, "netmask 0.0.0.0 dev", vifName)
		err = exec.Command("route", "del", "-net", "202.50.209.23", "gw", gateway, "netmask", "0.0.0.0", "dev", vifName).Run()
		log.Println("err is", err)
		//if err != nil {
		//	return err
		//}
		log.Println("start adding routing table")
		log.Println("route add -net 202.50.209.23 gw", gateway, "netmask 255.255.255.255 dev", localinterface)
		err = exec.Command("sudo", "route", "add", "-net", "202.50.209.23", "gw", gateway, "netmask", "255.255.255.255", "dev", localinterface).Run()
		log.Println("err is", err)

		//out, err := exec.Command("sudo", "netstat", "-r").Output()
		//log.Println(string(out))
		//if err != nil {
		//	return err
		//}
	}
	return nil
}

func NewDynVipInterface(localinterface string, macaddr string, vifName string) error {

	log.Println("ip", "link", "add", "link", localinterface, "address", macaddr, vifName, "type", "macvlan")
	err := exec.Command("ip", "link", "add", "link", localinterface, "address", macaddr, vifName, "type", "macvlan").Run()
	if err != nil {
		return err
	}

	log.Println("ip", "link", "set", vifName, "up")
	err = exec.Command("ip", "link", "set", vifName, "up").Run()
	if err != nil {
		return err
	}

	log.Println("dhclient", vifName)
	err = exec.Command("dhclient", vifName).Run()
	if err != nil {
		return err
	}
	//DeleteDuplicateRoute(localinterface, vifName)

	return nil
}

func DeleteVirtualif(vifName string) error {

	log.Println("ip", "link", "del", vifName)
	err := exec.Command("ip", "link", "del", vifName).Run()
	if err != nil {
		return err
	}

	return nil
}

func Addstaticrouting(remoteip string) error {
	log.Println("add static routing table")
	log.Println("route add -net", remoteip, "gw 10.8.0.5 netmask 255.255.255.255 dev tun0")
	err := exec.Command("sudo", "route", "add", "-net", remoteip, "gw", "10.8.0.5", "netmask", "255.255.255.255", "dev", "tun0").Run()
	log.Println("err is", err)
	return nil
}
func Delstaticrouting(remoteip string) error {
	log.Println("del static routing table")
	log.Println("route del -net", remoteip, "gw 10.8.0.5 netmask 255.255.255.255 dev tun0")
	err := exec.Command("sudo", "route", "del", "-net", remoteip, "gw", "10.8.0.5", "netmask", "255.255.255.255", "dev", "tun0").Run()
	log.Println("err is", err)
	return nil
}
func DelVIFstaticrouting(vifName string) error {
	out, err := exec.Command("ip", "route", "show").Output()
	if err != nil {
		log.Fatal(err)
	}

	if bytes.Contains(out, []byte(vifName)) {
		s := bytes.Fields(out)
		//fmt.Println("s is ", s)
		str := fmt.Sprintf("%s", s)
		fmt.Println("str", str)
		gateway := string(s[21])
		log.Println("gateway is ", gateway)
		log.Println("vifName is ", vifName)
		log.Println("route del -net", "192.168.1.0", "gw 0.0.0.0 netmask 0.0.0.0 dev", vifName)
		err = exec.Command("route", "del", "-net", "192.168.1.0", "gw", "0.0.0.0", "netmask", "255.255.255.0", "dev", vifName).Run()
		log.Println("err is", err)
	}
	return nil
}

func NewVIF(inport string, localip string, mask string) error {
	log.Println("sudo ifconfig", inport, localip, "netmask", mask, "up")
	err := exec.Command("/sbin/ifconfig", inport, localip, "netmask", mask, "up").Run()
	if err != nil {
		return err
	}
	return nil
}

func DeleteVIF(inport string, localip string) error {
	log.Println("sudo ifconfig", inport, localip, "down")
	err := exec.Command("/sbin/ifconfig", inport, localip, "down").Run()
	if err != nil {
		return err
	}
	return nil
}

func NewRoute(localip string, dstip string) error {
	log.Println("sudo iptables", "-t", "nat", "-A", "PREROUTING", "-d", localip, "-j", "DNAT", "--to-destination", dstip)
	cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-d", localip, "-j", "DNAT", "--to-destination", dstip)
	data, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(data))
		return err
	}

	return nil
}

func DeleteRoute(localip string, dstip string) error {
	log.Println("sudo iptables", "-t", "nat", "-D", "PREROUTING", "-d", localip, "-j", "DNAT", "--to-destination", dstip)
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-d", localip, "-j", "DNAT", "--to-destination", dstip)
	data, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(data))
		return err
	}

	return nil
}
func ResetVPN() error {
	log.Println("sudo service openvpn restart")
	cmd := exec.Command("sudo", "service", "openvpn", "restart")
	data, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(data))
		return err
	}

	return nil
}
