package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/gorilla/mux"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

var (
	ctx             = context.Background()
	cli, err        = client.NewEnvClient()
	swarmModeStatus = `{"Swarm_mode":false}`
	htmlOutput      = `<html> <script>
					function goBack()
					 { window.history.back() }
						</script>
						</head>
						<body>
						<button onclick="goBack()">Go Back</button>
						 </br>`
	buffer bytes.Buffer
)

// "Container" get container basic info
type Container struct {
	ID    string `json:"id,omitempty"`
	NAME  string `json:"name,omitempty"`
	IMAGE string `json:"image,omitempty"`
}

// var templates = template.Must(template.ParseFiles("edit.html", "view.html"))

func main() {

	if _, err := os.Stat("./ca.crt"); err == nil {
		fmt.Println("File crt exists")
	}
	if _, err := os.Stat("./ca.key"); err == nil {
		fmt.Println("File key exists")
	} else {
		fmt.Println("Files do not exits..creating")
		createCertificates()
	}

	r := mux.NewRouter().StrictSlash(true)
	router := r.Host(getIPAddr()).Subrouter()
	fmt.Printf("\n %v:10443 \n ", getIPAddr())
	// INDEX
	router.HandleFunc("/", usageInfoIndex).Methods("GET")

	// IMAGES
	router.HandleFunc("/images", listImages).Methods("GET")
	router.HandleFunc("/api/images", listImagesAPI).Methods("GET")
	router.HandleFunc("/api/images/{id}", selectImageInfo).Methods("GET")
	router.HandleFunc("/api/images/{id}", deleteImage).Methods("DELETE")

	// CONTAINERS
	router.HandleFunc("/containers", listContainers).Methods("GET")
	router.HandleFunc("/api/containers", listContainersAPI).Methods("GET")
	router.HandleFunc("/api/containers/{id}", selectContainerInfo).Methods("GET")
	router.HandleFunc("/api/containers/{id}/stop", stopContainer).Methods("POST")
	router.HandleFunc("/api/containers/{id}/start", startContainer).Methods("POST")
	router.HandleFunc("/api/prunecontainers", pruneContainers).Methods("DELETE")

	// VOLUMES
	router.HandleFunc("/volumes", listVolumes).Methods("GET")
	router.HandleFunc("/api/volumes", listVolumesAPI).Methods("GET")
	router.HandleFunc("/api/volumes/{name}", selectVolumeInfo).Methods("GET")

	// NETWORKS
	router.HandleFunc("/networks", listNetworks).Methods("GET")
	router.HandleFunc("/api/networks", listNetworksAPI).Methods("GET")
	router.HandleFunc("/api/networks/{id}", selectVolumeInfo).Methods("GET")

	// NODES
	router.HandleFunc("/nodes", swarmNodes).Methods("GET")
	router.HandleFunc("/api/nodes", swarmNodesAPI).Methods("GET")

	// SERVICES
	router.HandleFunc("/services", listServices).Methods("GET")
	router.HandleFunc("/api/services", listServicesAPI).Methods("GET")

	// TLS configuration
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// Server setup
	srv := &http.Server{
		Addr: "0.0.0.0:10443",
		// seting timeouts to avoid Slowloris attacks
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 15,
		Handler:      router,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	// this also helps with above potential problem
	go func() {
		if err := srv.ListenAndServeTLS("ca.crt", "ca.key"); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	// ctrl/cmd + c to stop it
	signal.Notify(c, os.Interrupt)

	<-c

}

// list all containers
func listContainers(w http.ResponseWriter, r *http.Request) {
	htmlOutput := htmlOutput
	for _, container := range returnContainers() {
		htmlOutput += strings.Join(container.Names, ",") + " | " + container.Image + " --- " + container.State + "<br/>"
	}
	htmlOutput += "</html>"
	fmt.Fprint(w, htmlOutput)
}

func listContainersAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(returnContainers())
}

func selectContainerInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	params := mux.Vars(r)
	for _, container := range returnContainers() {
		if strings.Contains(container.ID, params["id"]) {
			json.NewEncoder(w).Encode(container)
			return
		}
	}
}

// return list of networks
func listNetworks(w http.ResponseWriter, r *http.Request) {
	htmlOutput := htmlOutput
	htmlOutput += "Network Name | ID <br>"
	for _, network := range returnNetworks() {
		htmlOutput += network.Name + " | " + network.ID[:20] + "<br/>"
	}
	htmlOutput += "</html>"
	fmt.Fprint(w, htmlOutput)
}

func listNetworksAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(returnNetworks())
}

func selectNetworkInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	params := mux.Vars(r)
	for _, network := range returnNetworks() {
		if strings.Contains(network.ID, params["id"]) {
			json.NewEncoder(w).Encode(network)
			return
		}
	}
}

// return list of all images
func listImages(w http.ResponseWriter, r *http.Request) {
	//List all images available locally
	htmlOutput := htmlOutput
	htmlOutput += `ID => SIZE(MB) <br>`
	for _, image := range returnImages() {
		htmlOutput += image.ID[7:20] + " => " + strconv.Itoa(int(image.Size)/1024/1024) + "=> " + image.Labels["org.label-schema.name"] + "<br>"
	}
	htmlOutput += "</html>"
	fmt.Fprint(w, htmlOutput)
}

func listImagesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(returnImages())
}

func selectImageInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	params := mux.Vars(r)
	for _, image := range returnImages() {
		if strings.Contains(image.ID, params["id"]) {
			json.NewEncoder(w).Encode(image)
			return
		}
	}
}

// list all services
func listServices(w http.ResponseWriter, r *http.Request) {
	htmlOutput := htmlOutput
	services, err := returnServices()
	if err != nil {
		htmlOutput += "Docker is not in SWARM mode."
		fmt.Fprint(w, htmlOutput)
		return
	}
	for _, service := range services {
		htmlOutput += service.ID[:25] + "</br>"
	}
	htmlOutput += "</html>"
	fmt.Fprint(w, htmlOutput)
}

func listServicesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	services, err := returnServices()
	if err != nil {
		io.WriteString(w, swarmModeStatus)
		return
	}
	json.NewEncoder(w).Encode(services)
	return

}

func listVolumes(w http.ResponseWriter, r *http.Request) {
	htmlOutput := htmlOutput
	for _, volumes := range returnVolumes() {
		htmlOutput += volumes.Name + " | " + volumes.Driver + " | " + volumes.Mountpoint + "</br>"
	}
	htmlOutput += "</html>"
	fmt.Fprint(w, htmlOutput)
}

func listVolumesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(returnVolumes())
}

func selectVolumeInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	params := mux.Vars(r)
	for _, volume := range returnVolumes() {
		if strings.Contains(volume.Name, params["name"]) {
			json.NewEncoder(w).Encode(volume)
			return
		}
	}
}

// perform prune and return report
func volumePrune() types.VolumesPruneReport {
	volumes, err := cli.VolumesPrune(ctx, filters.Args{})
	if err != nil {
		panic(err)
	}
	return volumes
}

// works only in swarm mode
func swarmNodes(w http.ResponseWriter, r *http.Request) {
	htmlOutput := htmlOutput
	nodes, err := returnSwarmNodes()
	if err != nil {
		htmlOutput += "Docker is not in SWARM mode."
		fmt.Fprint(w, htmlOutput)
		return
	}
	//fmt.Println("Name | Role | Leader | Status")
	for _, swarmNode := range nodes {
		htmlOutput += swarmNode.Description.Hostname
	}
	htmlOutput += "</html>"
	fmt.Fprint(w, htmlOutput)

}

func swarmNodesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	nodes, err := returnSwarmNodes()
	if err != nil {
		io.WriteString(w, swarmModeStatus)
		return
	}
	json.NewEncoder(w).Encode(nodes)
	return
}

func returnContainers() []types.Container {
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}
	return containers
}

func returnImages() []types.ImageSummary {
	images, err := cli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		panic(err)
	}
	return images
}

func returnNetworks() []types.NetworkResource {
	networks, err := cli.NetworkList(ctx, types.NetworkListOptions{})
	if err != nil {
		panic(err)
	}
	return networks
}

func returnSwarmNodes() ([]swarm.Node, error) {
	swarmNodes, err := cli.NodeList(ctx, types.NodeListOptions{})
	if err != nil {
		return nil, err
	}
	return swarmNodes, err
}

func returnServices() ([]swarm.Service, error) {
	services, err := cli.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		return nil, err
	}
	return services, err
}

func returnVolumes() []*types.Volume {
	volumes, err := cli.VolumeList(ctx, filters.Args{})
	if err != nil {
		panic(err)
	}
	return volumes.Volumes
}

// delete image by ID
func deleteImage(w http.ResponseWriter, r *http.Request) {
	imageIDs := mux.Vars(r)
	var Image []Container
	for _, image := range returnImages() {
		for _, imageID := range imageIDs {
			if image.ID[7:20] == imageID {
				cli.ImageRemove(ctx, image.ID[7:20], types.ImageRemoveOptions{})
				Image = append(Image, Container{IMAGE: imageID})
			}
		}
	}
	json.NewEncoder(w).Encode(Image)
}

// stop container
func stopContainer(w http.ResponseWriter, r *http.Request) {
	containerIDs := mux.Vars(r)
	for _, container := range returnContainers() {
		for _, containerID := range containerIDs {
			switch {
			case strings.Contains(container.ID, containerID):
				cli.ContainerStop(ctx, container.ID, nil)
				return
			case container.Names[0][1:] == containerID:
				cli.ContainerStop(ctx, container.Names[0][1:], nil)
				return
			default:
				fmt.Println("Container doesn't exist")
				return
			}
		}
	}
}

// start a container
func startContainer(w http.ResponseWriter, r *http.Request) {
	containerIDs := mux.Vars(r)
	for _, container := range returnContainers() {
		for _, containerID := range containerIDs {
			switch {
			case strings.Contains(container.ID, containerID):
				cli.ContainerStart(ctx, container.ID, types.ContainerStartOptions{})
				return
			case container.Names[0][1:] == containerID:
				cli.ContainerStart(ctx, container.Names[0][1:], types.ContainerStartOptions{})
				return
			default:
				fmt.Println("Container doesn't exist")
				return
			}
		}
		json.NewEncoder(w).Encode(container.Names[0][1:] + " has started")
	}
}

// prune containers
func pruneContainers(w http.ResponseWriter, r *http.Request) {
	cli.ContainersPrune(ctx, filters.Args{})
}

// index page
func usageInfoIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "text/html")
	http.ServeFile(w, r, ".")
}

func getIPAddr() string {
	var add string
	host, _ := os.Hostname()
	addrs, _ := net.LookupIP(host)
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			add = ipv4.String()
		}
	}
	return add
}

func createCertificates() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{"SREstyle"},
			Country:      []string{"Serbia"},
			Locality:     []string{"Belgrade"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	caB, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}

	certOut, err := os.Create("ca.crt")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caB})
	certOut.Close()
	log.Print("written cert.pem\n")

	keyOut, err := os.OpenFile("ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written key.pem\n")
}
