package zeek

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"zaas/config"
)

type Zeek struct {
	sync.Mutex
	conf config.Config
}

func NewZeek(Conf config.Config) *Zeek {
	var zeek Zeek
	zeek.conf = Conf
	return &zeek
}

func (z *Zeek) Analyze(filePath string) error {
	z.Lock()
	defer z.Unlock()

	fileName := filePath[strings.LastIndex(filePath, "/")+1:]
	fileName = strings.ReplaceAll(fileName, ":", "_")

	filePath = z.conf.ZeekConf.PcapDir + "/" + fileName

	// "-C" disables checksum verification
	// @ref: https://github.com/hosom/file-extraction/issues/5
	zeekCmd := fmt.Sprintf("zeek -C -r %s local 'Site::local_nets += { 0.0.0.0/0 }'", filePath)
	cmd := exec.Command("sh", "-c", zeekCmd)
	cmd.Dir = z.conf.ZeekConf.LogDir

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
