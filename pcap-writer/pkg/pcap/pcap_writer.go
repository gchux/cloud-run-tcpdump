package pcap

import (
	"os"
	"io"
  "fmt"
  "log"
  "time"
  "unsafe"
  "reflect"
  "path/filepath"

  "github.com/easyCZ/logrotate"
  "github.com/itchyny/timefmt-go"
)

type PcapWriter interface {
  io.Writer
  io.Closer
} 

type pcapWriter struct {
  *logrotate.Writer
  v                reflect.Value
  osFile           reflect.Value
  osFileSync       reflect.Value
  bufioWriter      reflect.Value
  bufioWriterFlush reflect.Value
}

//go:linkname rotate github.com/easyCZ/logrotate.(*Writer).rotate
func rotate(w *logrotate.Writer)

func makeSetable(v reflect.Value) reflect.Value {
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

func getField(v reflect.Value, field string) reflect.Value {
  return v.Elem().FieldByName(field)
}

func getStableField(v reflect.Value, field string) reflect.Value {
  return makeSetable(getField(v, field))
}

func (w *pcapWriter) rotate() {
  // w.bufioWriterFlush.Call(nil)
  // w.osFileSync.Call(nil)

  // see: https://pkg.go.dev/cmd/compile#:~:text=//-,go%3Alinkname,-localname%20%5Bimportpath.name
  rotate(w.Writer)
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

  v := reflect.ValueOf(writer)

  // `logrotate` does not provide handles to flush the underlying file;
  // since PCAP engines are started atomically and current execution must complete
  // before a new one can be started; it is safe to `flush` and `sync` PCAP files.
  // https://github.com/easyCZ/logrotate/blob/master/writer.go
  osFile := getStableField(v, "f")
  osFileSync := osFile.MethodByName("Sync")
  
  bufioWriter := getStableField(v, "bw")
  bufioWriterFlush := bufioWriter.MethodByName("Flush")

  return &pcapWriter{writer, v, osFile, osFileSync, bufioWriter, bufioWriterFlush}, nil
}
