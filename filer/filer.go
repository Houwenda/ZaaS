package filer

import (
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"zaas/config"
)

type Client struct {
	conf       config.Config
	httpClient http.Client
}

func NewClient(Config config.Config) *Client {
	var client Client
	client.conf = Config
	return &client
}

func (c *Client) DownloadAndExtract(filePath string) error {
	if len(filePath) > 0 && string(filePath[0]) != "/" {
		filePath = "/" + filePath
	}
	getRequest, err := http.NewRequest("GET", "http://"+c.conf.SeaweedfsConf.Addr+filePath, nil)
	if err != nil {
		return err
	}
	getRequest.SetBasicAuth(c.conf.SeaweedfsConf.BasicUsername, c.conf.SeaweedfsConf.BasicPassword)

	resp, err := http.DefaultClient.Do(getRequest)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		log.Println(resp.Status)
		return errors.New(resp.Status)
	}
	defer resp.Body.Close()

	fileName := filePath[strings.LastIndex(filePath, "/")+1:]
	// ":" in filename causes problems on my exFAT SSD
	// @ref: https://unix.stackexchange.com/questions/299667/how-to-deal-with-characters-like-or-that-make-invalid-filenames
	fileName = strings.ReplaceAll(fileName, ":", "_")

	outFile, err := os.OpenFile(c.conf.ZeekConf.PcapDir+"/"+fileName,
		os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		return err
	}
	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return err
	}

	fmt.Println(strings.ToLower(filepath.Ext(fileName)))
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".pcap":
		log.Println("no need to decompress")
	case ".zstd":
		decompressedFileName := fileName[:strings.LastIndex(fileName, ".zstd")]
		err := decompress(c.conf.ZeekConf.PcapDir+"/"+decompressedFileName,
			c.conf.ZeekConf.PcapDir+"/"+fileName)
		if err != nil {
			return err
		}
		log.Println("decompressed")
	default:
		fmt.Println("unknown file format")
		return errors.New("unkown file format:" + strings.ToLower(filepath.Ext(fileName)))
	}

	return nil
}

func (c *Client) UploadExtractedFiles(filePath string) error {
	// filePath is remote pcap file path
	extractedFilenames := make([]string, 0)
	folder, err := os.Open(c.conf.ZeekConf.ExtractedFileDir)
	if err != nil {
		return err
	}
	fileInfos, err := folder.Readdir(-1)
	if err != nil {
		return err
	}
	for _, fileInfo := range fileInfos {
		extractedFilenames = append(extractedFilenames, fileInfo.Name())
	}

	for _, fileName := range extractedFilenames {
		fmt.Println("uploading:", fileName)
		err = c.upload(filePath, c.conf.ZeekConf.ExtractedFileDir+"/"+fileName)
		if err != nil {
			return err
		}
	}
	return nil
}

// upload local file to seaweedfs cluster
func (c *Client) upload(rawPath, localPath string) error {
	// rawPath is remote pcap file path
	// localPath is the path of file extracted by zeek
	fileName := localPath[strings.LastIndex(localPath, "/")+1:]
	rawFileName := rawPath[strings.LastIndex(rawPath, "/")+1:]

	var remoteDir string
	if c.conf.SeaweedfsConf.ExtractedFileDir[:1] == "/" {
		remoteDir = c.conf.SeaweedfsConf.ExtractedFileDir + "/" + rawFileName
	} else {
		remoteDir = "/" + c.conf.SeaweedfsConf.ExtractedFileDir + "/" + rawFileName
	}
	fullPath := "http://" + c.conf.SeaweedfsConf.Addr + remoteDir + "/" + fileName

	// http post with retries
	var err error
	retries := c.conf.SeaweedfsConf.Retries
	for retries > 0 {
		// prepare http post request
		// @ref: https://github.com/linxGnu/goseaweedfs/blob/master/http_client.go
		r, w := io.Pipe()
		mw := multipart.NewWriter(w)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Type", mime.TypeByExtension(strings.ToLower(filepath.Ext(fileName))))
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, fileName))

		fileReader, err := os.OpenFile(localPath, os.O_RDONLY, 0660)
		if err != nil {
			log.Println(err)
			return err
		}

		go func() {
			part, err := mw.CreatePart(h)
			if err == nil {
				_, err = io.Copy(part, fileReader)
			}
			if err == nil {
				if err = mw.Close(); err == nil {
					_ = w.Close()
				} else {
					_ = w.Close()
				}
			} else {
				_ = mw.Close()
				_ = w.Close()
			}
		}()

		// post request with basic authentication
		postRequest, err := http.NewRequest("POST", fullPath, r)
		if err != nil {
			return err
		}
		postRequest.Header.Add("Content-Type", mw.FormDataContentType())
		postRequest.SetBasicAuth(c.conf.SeaweedfsConf.BasicUsername, c.conf.SeaweedfsConf.BasicPassword)

		_, err = c.httpClient.Do(postRequest)
		if err != nil {
			log.Println(err)
			retries--
		} else {
			break
		}
	}

	if retries == 0 {
		return err
	}
	return nil
}
