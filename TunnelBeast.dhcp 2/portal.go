package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	//"time"

	//"TunnelBeast/auth"
	"TunnelBeast.dhcp/config"
	"TunnelBeast.dhcp/iptables"
)

var VIFid int = 0
var realport string
var connectionTable = map[string]string{}
var srcipVIFTable = map[string]string{}
var dynipVIFTable = map[string]string{}

var vmlistmap = map[string]string{}
var vmlist string

var dynIpAddr string
var dynIpMask string
var incr int = 1
var dynenableflag bool = false
var vifName string

const PORTAL_TEMPLATE = `
<html>
<head>
<style>
@import url(https://fonts.googleapis.com/css?family=Roboto:300);

.login-page {
  width: 360px;
  padding: 8% 0 0;
  margin: auto;
}
form {
  position: relative;
  z-index: 1;
  background: #FFFFFF;
  max-width: 360px;
  margin: 0 auto 100px;
  padding: 20px;
  text-align: center;
  box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
}
input {
  font-family: "Roboto", sans-serif;
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
select {
  font-family: "Roboto", sans-serif;
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
button {
  font-family: "Roboto", sans-serif;
  text-transform: uppercase;
  outline: 0;
  background: #4CAF50;
  width: 100%;
  border: 0;
  padding: 15px;
  color: #FFFFFF;
  font-size: 14px;
  -webkit-transition: all 0.3 ease;
  transition: all 0.3 ease;
  cursor: pointer;
}
body {
  background: #76b852; /* fallback for old browsers */
  background: -webkit-linear-gradient(right, #76b852, #8DC26F);
  background: -moz-linear-gradient(right, #76b852, #8DC26F);
  background: -o-linear-gradient(right, #76b852, #8DC26F);
  background: linear-gradient(to left, #76b852, #8DC26F);
  font-family: "Roboto", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
</style>
</head>
<body>
<div class="login-page" >
    <form class="login-form" action="/add" method="post">
			<button type="button" onclick="getDynamicIP()">Get A Dynamic IP</button>
			<input type="text" name="localip" id="localip" placeholder="localip"/>
			<input type="text" name="localmask" id="localmask" placeholder="localmask"/>
			<select name="remoteip">
				For {{range $k,$v := .}}
				<option value="{{$v}}">{{$k}} {{$v}}</option>
				{{end}}
			</select>
      <button type="submit">add a mapping</button>
			<p><a href="/list">Go to List Page</a></p>
			<p><a href="/delete">Go to Delete Page</a></p>
    </form>
</div>

<script>
function getDynamicIP() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      callback(this);
    }
  };
  xhttp.open("GET", "/dynip", true);
  xhttp.send();
}
function callback(xhttp) {
	var ipmask = xhttp.responseText;
	var sep = ipmask.split("&");
	document.getElementById("localip").value = sep[0]
	document.getElementById("localmask").value = sep[1]
}
</script>

</body>
</html>
`

const DELETE_TEMPLATE = `
<html>
<head>
<style>
@import url(https://fonts.googleapis.com/css?family=Roboto:300);

.login-page {
  width: 360px;
  padding: 8% 0 0;
  margin: auto;
}
form {
  position: relative;
  z-index: 1;
  background: #FFFFFF;
  max-width: 360px;
  margin: 0 auto 100px;
  padding: 20px;
  text-align: center;
  box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
}
button {
  font-family: "Roboto", sans-serif;
  text-transform: uppercase;
  outline: 0;
  background: #4CAF50;
  width: 100%;
  border: 0;
  padding: 15px;
  color: #FFFFFF;
  font-size: 14px;
  -webkit-transition: all 0.3 ease;
  transition: all 0.3 ease;
  cursor: pointer;
}
input {
  font-family: "Roboto", sans-serif;
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
body {
  background: #76b852; /* fallback for old browsers */
  background: -webkit-linear-gradient(right, #76b852, #8DC26F);
  background: -moz-linear-gradient(right, #76b852, #8DC26F);
  background: -o-linear-gradient(right, #76b852, #8DC26F);
  background: linear-gradient(to left, #76b852, #8DC26F);
  font-family: "Roboto", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
</style>
</head>
<body>
<div class="login-page" >
    <form class="login-form" action="/delete" method="get">
			<select name="localip">
				For {{range $k,$v := .}}
				<option value="{{$k}}">{{$k}} {{$v}}</option>
				{{end}}
			</select>
      <button type="submit">delete a mapping</button>
			<p><a href="/list">Go to List Page</a></p>
	    <p><a href="/">Go to Add Page</a></p>
    </form>
  </div>
</div>
</body>
</html>
`

const LIST_TEMPLATE = `
<html>
<head>
<style>
@import url(https://fonts.googleapis.com/css?family=Roboto:300);

.login-page {
  width: 360px;
  padding: 8% 0 0;
  margin: auto;
}
form {
  position: relative;
  z-index: 1;
  background: #FFFFFF;
  max-width: 360px;
  margin: 0 auto 100px;
  padding: 20px;
  text-align: center;
  box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
}
button {
  font-family: "Roboto", sans-serif;
  text-transform: uppercase;
  outline: 0;
  background: #4CAF50;
  width: 100%;
  border: 0;
  padding: 15px;
  color: #FFFFFF;
  font-size: 14px;
  -webkit-transition: all 0.3 ease;
  transition: all 0.3 ease;
  cursor: pointer;
}
input {
  font-family: "Roboto", sans-serif;
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
body {
  background: #76b852; /* fallback for old browsers */
  background: -webkit-linear-gradient(right, #76b852, #8DC26F);
  background: -moz-linear-gradient(right, #76b852, #8DC26F);
  background: -o-linear-gradient(right, #76b852, #8DC26F);
  background: linear-gradient(to left, #76b852, #8DC26F);
  font-family: "Roboto", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
</style>
</head>
<body>
<div class="login-page" >
    <form class="login-form" action="/list" method="get">
			<ul>
				{{range $k,$v := .}} <li>{{$k}}     {{$v}}</li> {{end}}
			</ul>
			<p><a href="/">Go to Add Page</a></p>
			<p><a href="/delete">Go to Delete Page</a></p>
    </form>
  </div>
</div>
</body>
</html>
`

func getipaddr(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	localIP := r.Form.Get("localip")
	netmask := r.Form.Get("localmask")
	remoteIP := r.Form.Get("remoteip")
	log.Println("localip", localIP)
	log.Println("netmask", netmask)
	log.Println("remoteIP", remoteIP)
	log.Println("dynipVIFTable", dynipVIFTable)
	log.Println("len", len(dynipVIFTable))
	if len(dynipVIFTable) > 0 {
		for key, value := range dynipVIFTable {
			log.Println("value of vif name", value)
			iptables.DeleteVirtualif(value)
			delete(dynipVIFTable, key)
		}
	}
	log.Println("dynipVIFTable", dynipVIFTable)

	var macaddr string
	if incr > 0 && incr < 10 {
		macaddr = "00:88:44:99:77:0" + strconv.Itoa(incr)
	} else if incr >= 10 && incr < 100 {
		macaddr = "00:88:44:99:77:" + strconv.Itoa(incr)
	} else {
		log.Println("too much hosts")
	}

	vifName = "virtual" + strconv.Itoa(incr)
	var ipandmask [2]string
	err := iptables.NewDynVipInterface(realport, macaddr, vifName)
	if err != nil {
		log.Println("Error iptables", err)
		return
	}
	ipandmask = iptables.GetIpFromVif(vifName)
	dynIpAddr = ipandmask[0]
	dynIpMask = ipandmask[1]

	dynipVIFTable[dynIpAddr] = vifName
	log.Println("dynipVIFTable", dynipVIFTable)
	fmt.Println("dynIpAddr", dynIpAddr)
	fmt.Println("dynIpMask", dynIpMask)
	incr = incr + 1
	dynenableflag = true
	w.Write([]byte(dynIpAddr + "&" + dynIpMask))
}

func getServerList(pn string, u string, pw string, pi string, projectNetwork string) {
	//jet user
	//text := `{"auth": {"scope": {"project": {"domain": {"name": "default"}, "name": "fred"}}, "identity": {"password": {"user": {"domain": {"name": "default"}, "password": "cics2905", "name": "jet.lau@gmail.com"}}, "methods": ["password"]}}}`
	//admin
	text := "{\"auth\": {\"scope\": {\"project\": {\"domain\": {\"name\": \"default\"}, \"name\": \"" + pn + "\"}}, \"identity\": {\"password\": {\"user\": {\"domain\": {\"name\": \"default\"}, \"password\": \"" + pw + "\", \"name\": \"" + u + "\"}}, \"methods\": [\"password\"]}}}"
	urlstr := "http://192.168.1.240:35357/v3/auth/tokens"

	req, _ := http.NewRequest("POST", urlstr, bytes.NewBuffer([]byte(text)))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	fmt.Println("token:", resp.Header["X-Subject-Token"])
	fmt.Println("==============================================================")
	restapitoken := strings.Join(resp.Header["X-Subject-Token"], "")
	fmt.Println("restapitoken:", restapitoken)
	fmt.Println("==============================================================")

	//jet user
	//url := "http://192.168.1.240:8774/v2.1/7cb24d7bfe0a4041aaf2d1b4cdb06d87/servers/detail"
	//admin
	url := "http://192.168.1.240:8774/v2.1/" + pi + "/servers/detail"
	reqserver, _ := http.NewRequest("GET", url, nil)
	reqserver.Header.Set("X-Auth-Token", restapitoken)

	clientlist := &http.Client{}
	resplist, err := clientlist.Do(reqserver)
	if err != nil {
		panic(err)
	}
	defer resplist.Body.Close()
	body, _ := ioutil.ReadAll(resplist.Body)
	//fmt.Println("response Body:", string(body))

	fmt.Println("===================================================")

	mapserver := make(map[string]interface{})

	errlist := json.Unmarshal(body, &mapserver)
	if errlist != nil {
		panic(errlist)
	}
	//projectnetwork := pn + "network"
	//projectNetwork := pn + "Network"
	fmt.Println("projectnetwork:", projectNetwork)
	//fmt.Println("mapserver:", mapserver)

	for _, value := range mapserver {
		for _, v := range value.([]interface{}) {
			name := v.(map[string]interface{})["name"]
			mapaddr := v.(map[string]interface{})["addresses"].(map[string]interface{})
			fmt.Println("name:", name)
			fmt.Println("mapaddr:", mapaddr)
			for _, u := range mapaddr {
				adminnet := u.([]interface{})
				fmt.Println("adminnet:", adminnet)
				if len(adminnet) > 1 {
					addr := adminnet[1].(map[string]interface{})
					fmt.Println("addr:", addr)
					vmlistmap[name.(string)] = addr["addr"].(string)
					fmt.Println("name:", name, "ip addr:", addr["addr"])
				}
			}
		}
	}
	for key, value := range vmlistmap {
		vmlistline := "<option value=\"key\">" + key + " " + value + "</option>"
		vmlist = vmlist + vmlistline + "\n"
	}
	fmt.Println(vmlist)
}

func showlist(w http.ResponseWriter, r *http.Request) {
	check := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	t, err := template.New("listpage").Parse(LIST_TEMPLATE)
	check(err)

	t.Execute(w, connectionTable)
	check(err)
	//t.Execute(os.Stdout, connectionTable)

	//w.Write([]byte("\nvirtual interface, localIP, remoteIP\n"))
	//for key, value := range srcipVIFTable {
	//	result := value + "," + key + "," + connectionTable[key] + "\n"
	//	w.Write(([]byte(result)))
	//}
	//w.Write([]byte("\nplease click \"go back\" or type http://localhost:666 on browers to back to the main page\n"))
}

func AddHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("entry AddHandler")
	//username := r.URL.Query().Get("username")
	//password := r.URL.Query().Get("password")

	//localIP := r.URL.Query().Get("localip")
	//netmask := r.URL.Query().Get("localmask")
	//remoteIP := r.URL.Query().Get("remoteip")
	r.ParseForm()
	localIP := r.Form.Get("localip")
	netmask := r.Form.Get("localmask")
	remoteIP := r.Form.Get("remoteip")
	log.Println("localip", localIP)
	log.Println("netmask", netmask)
	log.Println("remoteIP", remoteIP)

	//if username == "" || password == "" || remoteIP == "" {
	if localIP == "" || netmask == "" || remoteIP == "" {
		w.Write([]byte("ERROR"))
		return
	}
	//localIP := strings.Split(r.RemoteAddr, ":")[0]
	//if _, exists := connectionTable[localIP]; exists {
	//	w.Write([]byte("LOGGEDIN"))
	//	return
	//}

	inport := realport + ":" + strconv.Itoa(VIFid)
	VIFid++
	if dynenableflag == false {
		err := iptables.NewVIF(inport, localIP, netmask)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		srcipVIFTable[localIP] = inport
	} else {
		srcipVIFTable[localIP] = vifName
	}

	err := iptables.Addstaticrouting(remoteIP)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	err = iptables.DelVIFstaticrouting(vifName)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	//w.Write([]byte("virtual interface created\n"))

	//if authProvider.Authenticate(username, password, remoteIP) {

	err = iptables.NewRoute(localIP, remoteIP)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	connectionTable[localIP] = remoteIP
	delete(dynipVIFTable, localIP)
	log.Println("connectiontTable", connectionTable)
	log.Println("dynipVIFTable", dynipVIFTable)
	//w.Write([]byte("iptables created\n"))

	//showlist(w, r)
	//http.Redirect(w, r, "localhost:666/list", http.StatusSeeOther)
	http.Redirect(w, r, "/list", 301)

}

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("delete request")

	check := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	t, err := template.New("deletepage").Parse(DELETE_TEMPLATE)
	check(err)

	t.Execute(w, connectionTable)
	check(err)

	localIP := r.URL.Query().Get("localip")
	log.Println(localIP)
	log.Println(connectionTable)
	log.Println(dynenableflag)
	if localIP != "" {
		if remoteIP, exists := connectionTable[localIP]; exists {
			if dynenableflag == false {
				err := iptables.DeleteVIF(srcipVIFTable[localIP], localIP)
				if err != nil {
					w.Write([]byte(err.Error()))
					return
				}
			} else {
				err := iptables.DeleteVirtualif(srcipVIFTable[localIP])
				if err != nil {
					w.Write([]byte(err.Error()))
					return
				}
			}

			err := iptables.DeleteRoute(localIP, remoteIP)
			if err != nil {
				w.Write([]byte(err.Error()))
				return
			}
			err = iptables.Delstaticrouting(remoteIP)
			if err != nil {
				w.Write([]byte(err.Error()))
				return
			}

			delete(connectionTable, localIP)
			delete(srcipVIFTable, localIP)

			return
		}
		http.Redirect(w, r, "/list", 301)
	}

}

func PortalEntryHandler(w http.ResponseWriter, r *http.Request) {

	check := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	t, err := template.New("webpage").Parse(PORTAL_TEMPLATE)
	check(err)

	log.Println("Portal access", r.RemoteAddr)

	t.Execute(w, vmlistmap)
	check(err)

	//getipaddr("eth0")

	//t.Execute(os.Stdout, vmlistmap)

}

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Usage: TunnelBeast /path/to/config.yml")
	}
	conf := config.Configuration{}
	config.LoadConfig(os.Args[1], &conf)
	log.Printf("%+v\n", conf)

	//authProvider = conf.AuthProvider
	//authProvider.Init()

	realport = conf.ListenDev

	err := iptables.Init(conf.Outport)
	if err != nil {
		log.Println("Error initializing iptables", err)
		return
	}
	getServerList(conf.Projectname, conf.User, conf.Password, conf.Projectid, conf.Projectnetwork)

	mux := http.NewServeMux()
	mux.HandleFunc("/", PortalEntryHandler)
	mux.HandleFunc("/add", AddHandler)
	mux.HandleFunc("/delete", DeleteHandler)
	mux.HandleFunc("/list", showlist)
	mux.HandleFunc("/dynip", getipaddr)

	port80 := &http.Server{Addr: ":80", Handler: mux}
	port666 := &http.Server{Addr: ":666", Handler: mux}
	go func() {
		errInternal := port80.ListenAndServe()
		if errInternal != nil {
			log.Println(errInternal)
		}
	}()
	err = port666.ListenAndServe()
	if err != nil {
		log.Println(err)
	}

}
