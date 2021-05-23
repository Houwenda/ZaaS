package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"zaas/config"
	"zaas/filer"
	"zaas/zeek"
)

// Conf is configuration of analyzer
var (
	Conf  config.Config
	Filer *filer.Client
	Zeek  *zeek.Zeek
	err   error
)

func init() {
	// Read & parse config
	var configPath string
	if len(os.Args) != 2 {
		fmt.Println("no config file provided")
		configPath = "/etc/ZaaS/ZaaS.yml"
	} else {
		configPath = os.Args[1]
	}
	fmt.Println("reading config from " + configPath)
	Conf, err = Conf.Parse(configPath)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Check for misconfigurations
	if err = Conf.Validate(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Create logger
	if Conf.LogConf.Level == "debug" { // remove past log file
		if err := os.Remove(Conf.LogConf.Path); err != nil && os.IsExist(err) {
			fmt.Println("error removing past log file at " + Conf.LogConf.Path)
			os.Exit(1)
		}
	}
	logFile, logError := os.OpenFile(Conf.LogConf.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logError != nil {
		fmt.Println("unable to open or create log file at " + Conf.LogConf.Path)
		os.Exit(1)
	}
	log.SetOutput(logFile)
	log.Println("logging starts")

}

func main() {
	fmt.Println("ZaaS starts")

	Filer = filer.NewClient(Conf)
	Zeek = zeek.NewZeek(Conf)

	RestServer()
}

// RestServer offers a restful api
func RestServer() {
	http.HandleFunc("/"+Conf.ServerConf.RestAPIEndpoint, restHandler)
	srv := &http.Server{
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// make sure the server listen on ipv4
	listen4, err := net.Listen("tcp4", Conf.ServerConf.RestAPIIP+":"+strconv.Itoa(int(Conf.ServerConf.RestAPIPort)))
	if err != nil {
		panic(err)
	}

	fmt.Println("restful api running on http://" + Conf.ServerConf.RestAPIIP + ":" + strconv.Itoa(int(Conf.ServerConf.RestAPIPort)) + "/" + Conf.ServerConf.RestAPIEndpoint)
	srv.Serve(listen4)
}

func restHandler(w http.ResponseWriter, r *http.Request) {
	filePaths, ok := r.URL.Query()["path"]
	if !ok || len(filePaths) < 1 {
		log.Println("missing parameter: path")
		w.Write([]byte("missing parameter"))
	}

	w.Write([]byte("zaas processing"))
	for _, filePath := range filePaths {
		fmt.Println("path:", filePath)
		err := Filer.DownloadAndExtract(filePath)
		if err != nil {
			log.Println(err)
			cleanup()
			break
		}
		fmt.Println("downloaded and extracted")

		err = Zeek.Analyze(filePath)
		if err != nil {
			log.Println(err)
			cleanup()
			break
		}

		err = Filer.UploadExtractedFiles(filePath)
		if err != nil {
			log.Println(err)
			cleanup()
			break
		}

		cleanup()
	}
}

func cleanup() {
	cleanCmd := fmt.Sprintf("rm -f %s/*", Conf.ZeekConf.ExtractedFileDir)
	cmd := exec.Command("sh", "-c", cleanCmd)
	if err := cmd.Run(); err != nil {
		log.Println("error cleaning up extracted files dir")
	}
	cleanCmd = fmt.Sprintf("rm -f %s/*", Conf.ZeekConf.PcapDir)
	cmd = exec.Command("sh", "-c", cleanCmd)
	if err := cmd.Run(); err != nil {
		log.Println("error cleaning up pcap dir")
	}
}
