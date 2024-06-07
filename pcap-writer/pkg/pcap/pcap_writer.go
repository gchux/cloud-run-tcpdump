package pcap

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"time"
	"unsafe"

	"dario.cat/mergo"
	"github.com/easyCZ/logrotate"
	"github.com/itchyny/timefmt-go"
)

type PcapWriter interface {
	io.Writer
	io.Closer
	rotate()
}

type pcapWriter struct {
	*logrotate.Writer
	v                reflect.Value
	osFile           reflect.Value
	osFileSync       reflect.Value
	bufioWriter      reflect.Value
	bufioWriterFlush reflect.Value
	isStdOutOrErr    bool
}

//go:linkname rotate github.com/easyCZ/logrotate.(*Writer).rotate
func rotate(w *logrotate.Writer)

func makeSetable(v reflect.Value) reflect.Value {
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

func getField(v reflect.Value, field string) reflect.Value {
	return v.Elem().FieldByName(field)
}

func getSetableField(v reflect.Value, field string) reflect.Value {
	return makeSetable(getField(v, field))
}

func (w *pcapWriter) rotate() {
	// if `PcapWriter` encapsulates `std[out|err]` do not rotate,
	// just call `Flush` on the underlying `bufio.Writer` for `os.Stdout`
	if w.isStdOutOrErr {
		// w.osFileSync.Call(nil)
		w.bufioWriterFlush.Call(nil)
		return
	}

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

func getPcapWriterLocation() *time.Location {
	timezone, timezoneExists := os.LookupEnv("PCAP_TIMEZONE")
	if !timezoneExists {
		return time.UTC
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return time.UTC
	}
	return location
}

func getFileNameProvider(template *string) *pcapFileNameProvider {
	fileNameTemplate := *template
	return &pcapFileNameProvider{
		directory: filepath.Dir(fileNameTemplate),
		template:  filepath.Base(fileNameTemplate),
		location:  getPcapWriterLocation(),
	}
}

var defaultLogrotateOptions logrotate.Options = logrotate.Options{
	Directory:            "/",
	MaximumFileSize:      0,
	MaximumLifetime:      0,
	FlushAfterEveryWrite: false,
	FileNameFunc:         func() string { return "" },
}

func getPcapWriterForStdout(logger *log.Logger) (*logrotate.Writer, error) {
	return logrotate.New(logger, defaultLogrotateOptions)
}

func getPcapWriter(logger *log.Logger, template, extension *string, interval *int) (*logrotate.Writer, error) {
	var fileMaxLifetime time.Duration = time.Minute
	if *interval > 0 {
		fileMaxLifetime = time.Duration(*interval) * time.Second
	}

	fileNameTemplate := fmt.Sprintf("%s.%s", *template, *extension)
	fileNameProvider := getFileNameProvider(&fileNameTemplate)

	options := logrotate.Options{
		Directory:       fileNameProvider.directory,
		MaximumLifetime: fileMaxLifetime,
		FileNameFunc:    func() string { return fileNameProvider.get() },
	}

	if err := mergo.Merge(&options, defaultLogrotateOptions); err != nil {
		return nil, err
	}

	return logrotate.New(logger, options)
}

func isStdoutPcapWriter(template, extension *string, interval *int) bool {
	return ((template == nil && extension == nil) || (*template == "stdout" || *template == "stderr")) && *interval == 0
}

func NewStdoutPcapWriter() (PcapWriter, error) {
	return NewPcapWriter(nil, nil, 0)
}

func NewPcapWriter(template, extension *string, interval int) (PcapWriter, error) {
	isStdOutOrErr := isStdoutPcapWriter(template, extension, &interval)
	logger := log.New(os.Stderr, "[pcap/rotate] - ", log.LstdFlags)

	var err error
	var writer *logrotate.Writer

	if isStdOutOrErr {
		// Using `logrotate` to make `os.Stdout` safe to be concurrently written by PCAP engines
		writer, err = getPcapWriterForStdout(logger)
	} else {
		writer, err = getPcapWriter(logger, template, extension, &interval)
	}

	if err != nil {
		return nil, err
	}

	// `logrotate` does not provide handles to `*bufio.Writer::Flush`/`*os.File::Syinc`
	// the underlying Writer/File so it is necessary to get handles on them.
	// Since PCAP engines are started atomically and current execution must complete
	// before a new one can be started; it is safe to `flush` and `sync` PCAP files.
	// https://github.com/easyCZ/logrotate/blob/master/writer.go
	v := reflect.ValueOf(writer)
	osFile := getSetableField(v, "f")
	osFileSync := osFile.MethodByName("Sync")
	bufioWriter := getSetableField(v, "bw")
	bufioWriterFlush := bufioWriter.MethodByName("Flush")

	if isStdOutOrErr {
		// injecting `os.Stdout` into `logrotate.Writer` instance
		osFile.Set(reflect.ValueOf(os.Stdout))
		bufioWriter.Set(reflect.ValueOf(bufio.NewWriterSize(os.Stdout, 1)))
	}

	return &pcapWriter{writer, v, osFile, osFileSync, bufioWriter, bufioWriterFlush, isStdOutOrErr}, nil
}
