package pcap

import (
	"os"
	"io"
  "fmt"
  "log"
  "time"
  "path/filepath"

  "github.com/easyCZ/logrotate"
  "github.com/itchyny/timefmt-go"
)

type PcapWriter interface {
  io.Writer
  io.Closer
} 

type pcapFileNameProvider struct {
  directory string
  template  string
  location  *time.Location
}

func (p *pcapFileNameProvider) get() string {
	return timefmt.Format(time.Now().In(p.location), p.template)
}

func NewPcapWriter(template, extension *string, rotateSecs int) (PcapWriter, error) {

	if *template == "stdout" {
		return os.Stdout, nil
	}

	timezone, exists := os.LookupEnv("PCAP_TIMEZONE")
  if !exists {
    timezone = "UTC"
  }

  var err error
  var location *time.Location

  location, err = time.LoadLocation(timezone)
  if err != nil {
  	return nil, err
  }

	logger := log.New(os.Stderr, "[pcap/rotate] - ", log.LstdFlags)

	fileNameTemplate := fmt.Sprintf("%s.%s", *template, *extension)
	
  nameProvider := &pcapFileNameProvider{
		directory: filepath.Dir(fileNameTemplate),
		template:  filepath.Base(fileNameTemplate),
		location:  location,
  }

	writer, err := logrotate.New(logger, logrotate.Options{
		Directory:       nameProvider.directory,
		MaximumLifetime: time.Duration(rotateSecs) * time.Second,
    FileNameFunc:    func() string { return nameProvider.get() },
	})

	if err != nil {
		return nil, err
	}

  return writer, nil
}
