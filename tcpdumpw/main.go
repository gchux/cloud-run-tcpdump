// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	// _ "net/http/pprof"
	_ "time/tzdata"

	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/lrita/cmap"
)

func UNUSED(x ...interface{}) {}

var (
	use_cron   = flag.Bool("use_cron", false, "perform packet capture at specific intervals")
	cron_exp   = flag.String("cron_exp", "", "stardard cron expression; i/e: '1 * * * *'")
	timezone   = flag.String("timezone", "UTC", "TimeZone to be used to schedule packet captures")
	duration   = flag.Int("timeout", 0, "perform packet capture during this mount of seconds")
	interval   = flag.Int("interval", 60, "seconds after which tcpdump rotates PCAP files")
	snaplen    = flag.Int("snaplen", 0, "bytes to be captured from each packet")
	filter     = flag.String("filter", "", "BPF filter to be used for capturing packets")
	extension  = flag.String("extension", "pcap", "extension to be used for tcpdump PCAP files")
	directory  = flag.String("directory", "", "directory where PCAP files will be stored")
	tcp_dump   = flag.Bool("tcpdump", true, "enable JSON PCAP using tcpdump")
	json_dump  = flag.Bool("jsondump", false, "enable JSON PCAP using gopacket")
	json_log   = flag.Bool("jsonlog", false, "enable JSON PCAP to stardard output")
	ordered    = flag.Bool("ordered", false, "write JSON PCAP output as obtained from gopacket")
	conntrack  = flag.Bool("conntrack", false, "enable connection tracking ('ordered' is also enabled)")
	gcp_gae    = flag.Bool("gae", false, "enable GAE Flex environment configuration")
	pcap_iface = flag.String("iface", "", "prefix to scan for network interfaces to capture from")
	hc_port    = flag.Uint("hc_port", 12345, "TCP port for health checking")
)

var (
	ifacePrefixEnvVar string = os.Getenv("PCAP_IFACE")
	sidecarEnvVar     string = os.Getenv("APP_SIDECAR")
	moduleEnvVar      string = os.Getenv("PROC_NAME")
	gaeEnvVar         string = os.Getenv("GCP_GAE")
	hcPortEnvVar      string = os.Getenv("PCAP_HC_PORT")
)

var (
	jobs            cmap.Map[uuid.UUID, *tcpdumpJob]
	jid, xid        atomic.Value
	emptyTcpdumpJob = tcpdumpJob{Jid: uuid.Nil.String()}

	tcpdumpDisabledErr  = errors.New("GCS PCAP export disabled")
	jsondumpDisabledErr = errors.New("GCS JSON export disabled")
	jsonLogDisabledErr  = errors.New("STDOUT JSON log disabled")
	gaeDisabledErr      = errors.New("GAE JSON log disabled")
)

type (
	pcapTask struct {
		engine  pcap.PcapEngine   `json:"-"`
		writers []pcap.PcapWriter `json:"-"`
	}

	tcpdumpJob struct {
		j     *gocron.Job     `json:"-"`
		Xid   string          `json:"xid,omitempty"`
		Jid   string          `json:"jid,omitempty"`
		Name  string          `json:"name,omitempty"`
		Tags  []string        `json:"-"`
		tasks []*pcapTask     `json:"-"`
		ctx   context.Context `json:"-"`
	}

	jLogLevel string

	jLogEntry struct {
		Severity jLogLevel  `json:"severity"`
		Message  string     `json:"message"`
		Sidecar  string     `json:"sidecar"`
		Module   string     `json:"module"`
		Job      tcpdumpJob `json:"job,omitempty"`
		Tags     []string   `json:"tags,omitempty"`
	}
)

const (
	INFO  jLogLevel = "INFO"
	ERROR jLogLevel = "ERROR"
	FATAL jLogLevel = "FATAL"

	fileNamePattern = "%d_%s__%%Y%%m%%dT%%H%%M%%S"
	runFileOutput   = `%s/part__` + fileNamePattern
	gaeFileOutput   = `/var/log/app_engine/app/app_pcap__` + fileNamePattern
	gaeJSONInterval = 0 // disable time based file rotation
)

func jlog(severity jLogLevel, job *tcpdumpJob, message string) {
	j := *job
	j.Xid = xid.Load().(uuid.UUID).String()

	entry := &jLogEntry{
		Severity: severity,
		Message:  message,
		Sidecar:  sidecarEnvVar,
		Module:   moduleEnvVar,
		Job:      j,
		Tags:     j.Tags,
	}

	jEntry, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] - %s\n", err)
		return
	}
	fmt.Println(string(jEntry))
}

func afterTcpdump(id uuid.UUID, name string) {
	if job, ok := jobs.Load(id); ok {
		jlog(INFO, job, "execution complete")
		j := *job.j
		nextRun, _ := j.NextRun()
		jlog(INFO, job, fmt.Sprintf("next execution: %v", nextRun))
	}
	xid.Store(uuid.Nil) // reset execution id
}

func beforeTcpdump(id uuid.UUID, name string) {
	if job, ok := jobs.Load(id); ok {
		j := *job.j
		lastRun, _ := j.LastRun()
		jlog(INFO, job, fmt.Sprintf("execution started ( last execution: %v )", lastRun))
	}
	xid.Store(uuid.New())
}

func start(ctx context.Context, timeout time.Duration, job *tcpdumpJob) error {
	// all PCAP engines are context aware
	var wg sync.WaitGroup
	wg.Add(len(job.tasks))

	var cancel context.CancelFunc
	if timeout > 0*time.Second {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	for _, task := range job.tasks {
		go func(ctx context.Context, t *pcapTask) {
			defer wg.Done()
			err := t.engine.Start(ctx, t.writers)
			if err != nil {
				jlog(INFO, job, fmt.Sprintf("pcap execution stopped: %s", err))
			}
		}(ctx, task)
	}

	// wait for context cancel/timeout
	<-ctx.Done()

	// wait for tasks to gracefully stop
	wg.Wait()

	return nil
}

func tcpdump(timeout time.Duration) error {
	jobID := jid.Load().(uuid.UUID)
	exeID := xid.Load().(uuid.UUID).String()

	var job *tcpdumpJob
	var ok bool
	if job, ok = jobs.Load(jobID); !ok {
		message := fmt.Sprintf("job[id:%s] not found", jobID)
		jlog(ERROR, &emptyTcpdumpJob, message)
		return fmt.Errorf(message)
	}

	// enable PCAP tasks with context awareness
	id := fmt.Sprintf("job/%s/exe/%s", jobID.String(), exeID)
	ctx := context.WithValue(job.ctx, pcap.PcapContextID, id)
	ctx = context.WithValue(ctx, pcap.PcapContextLogName,
		fmt.Sprintf("projects/%s/pcap/%s", os.Getenv("PROJECT_ID"), id))

	return start(ctx, timeout, job)
}

func newPcapConfig(
	iface, format, output, extension, filter string,
	snaplen, interval int,
	ordered, conntrack bool,
) *pcap.PcapConfig {
	return &pcap.PcapConfig{
		Promisc:   true,
		Iface:     iface,
		Snaplen:   snaplen,
		TsType:    "",
		Format:    format,
		Output:    output,
		Extension: extension,
		Filter:    filter,
		Interval:  interval,
		Ordered:   ordered,
		ConnTrack: conntrack,
	}
}

func createTasks(
	ifacePrefix, timezone, directory, extension, filter *string,
	snaplen, interval *int,
	tcpdump, jsondump, jsonlog, ordered, conntrack, gcpGAE *bool,
) []*pcapTask {
	tasks := []*pcapTask{}

	iface := ifacePrefixEnvVar
	if iface == "" {
		iface = *ifacePrefix
	}

	isGAE, err := strconv.ParseBool(gaeEnvVar)
	isGAE = (err == nil && isGAE) || *gcpGAE

	ifaceRegexp := regexp.MustCompile(fmt.Sprintf("^(?:(?:lo$)|(?:(?:ipvlan-)?%s\\d+.*$))", iface))
	devices, _ := pcap.FindDevicesByRegex(ifaceRegexp)

	for _, device := range devices {

		netIface := device.NetInterface
		iface := netIface.Name
		ifaceAndIndex := fmt.Sprintf("%d/%s", netIface.Index, iface)

		jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configuring PCAP for iface: %s", ifaceAndIndex))

		output := fmt.Sprintf(runFileOutput, *directory, netIface.Index, netIface.Name)

		tcpdumpCfg := newPcapConfig(iface, "pcap", output, *extension, *filter, *snaplen, *interval, *ordered, *conntrack)
		jsondumpCfg := newPcapConfig(iface, "json", output, "json", *filter, *snaplen, *interval, *ordered, *conntrack)

		// premature optimization is the root of all evil
		var engineErr, writerErr error = nil, nil
		var tcpdumpEngine, jsondumpEngine pcap.PcapEngine = nil, nil
		var jsondumpWriter, jsonlogWriter, gaejsonWriter pcap.PcapWriter = nil, nil, nil // `tcpdump` does not use custom writers

		if *tcpdump {
			tcpdumpEngine, engineErr = pcap.NewTcpdump(tcpdumpCfg)
		} else {
			engineErr = tcpdumpDisabledErr
		}
		if engineErr == nil {
			tasks = append(tasks, &pcapTask{engine: tcpdumpEngine, writers: nil})
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured 'tcpdump' for iface: %s", ifaceAndIndex))
		} else if *tcpdump {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("tcpdump GCS writer creation failed: %s (%s)", ifaceAndIndex, engineErr))
		}

		// skip JSON setup if JSON pcap is disabled
		if !*jsondump && !*jsonlog {
			continue
		}

		engineErr = nil
		jsondumpCfg.Ordered = *ordered

		// some form of JSON packet capturing is enabled
		jsondumpEngine, engineErr = pcap.NewPcap(jsondumpCfg)
		if engineErr != nil {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump task creation failed: %s (%s)", ifaceAndIndex, engineErr))
			continue // abort all JSON setup for this device
		}

		pcapWriters := []pcap.PcapWriter{}

		if *jsondump {
			// writing JSON PCAP file is only enabled if `jsondump` is enabled
			jsondumpWriter, writerErr = pcap.NewPcapWriter(&output, &jsondumpCfg.Extension, timezone, *interval)
		} else {
			jsondumpWriter, writerErr = nil, jsondumpDisabledErr
		}
		if writerErr == nil {
			pcapWriters = append(pcapWriters, jsondumpWriter)
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured JSON '%s' writer for iface: %s", output, ifaceAndIndex))
		} else if *jsondump {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump GCS writer creation failed: %s (%s)", ifaceAndIndex, writerErr))
		}

		// add `/dev/stdout` as an additional PCAP writer
		if *jsonlog {
			jsonlogWriter, writerErr = pcap.NewStdoutPcapWriter()
		} else {
			jsonlogWriter, writerErr = nil, jsonLogDisabledErr
		}
		if writerErr == nil {
			pcapWriters = append(pcapWriters, jsonlogWriter)
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured JSON 'stdout' writer for iface: %s", ifaceAndIndex))
		} else if *jsonlog {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump stdout writer creation failed: %s (%s)", ifaceAndIndex, writerErr))
		}

		// handle GAE JSON logger
		gaeOutput := ""
		if isGAE {
			gaeOutput = fmt.Sprintf(gaeFileOutput, netIface.Index, netIface.Name)
			gaejsonWriter, writerErr = pcap.NewPcapWriter(&gaeOutput, &jsondumpCfg.Extension, timezone, *interval)
		} else {
			gaejsonWriter, writerErr = nil, gaeDisabledErr
		}
		if writerErr == nil {
			pcapWriters = append(pcapWriters, gaejsonWriter)
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured GAE JSON '%s' writer for iface: %s", gaeOutput, ifaceAndIndex))
		} else if isGAE {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump GAE json writer creation failed: %s (%s)", ifaceAndIndex, gaeDisabledErr))
		}

		jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured 'jsondump' for iface: %s", ifaceAndIndex))
		tasks = append(tasks, &pcapTask{jsondumpEngine, pcapWriters})
	}

	return tasks
}

func startTCPListener(ctx context.Context, port *uint, stopChannel chan<- bool) {
	tcpListener, tcpListenerErr := net.Listen("tcp", fmt.Sprintf(":%d", *port))

	if tcpListenerErr != nil {
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("failed to start the TCP listener: %v", tcpListenerErr))
		os.Exit(4)
	}

	for {
		select {
		case <-ctx.Done():
			var err error
			if err = tcpListener.Close(); err != nil {
				jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("failed to stop the TCP listener: %v", err))
			}
			stopChannel <- (err == nil)
			return

		// accept connections until context is done
		default:
			conn, err := tcpListener.Accept()
			if err != nil {
				conn.Close()
			}
		}
	}
}

func main() {
	flag.Parse()

	jid.Store(uuid.Nil)
	xid.Store(uuid.Nil)

	jlog(INFO, &emptyTcpdumpJob,
		fmt.Sprintf("args[iface:%s|use_cron:%t|cron_exp:%s|timezone:%s|timeout:%d|extension:%s|directory:%s|snaplen:%d|filter:%s|interval:%d|tcpdump:%t|jsondump:%t|jsonlog:%t|ordered:%t|hc_port:%d|gcp_gae:%t]",
			*pcap_iface, *use_cron, *cron_exp, *timezone, *duration, *extension, *directory, *snaplen, *filter, *interval, *tcp_dump, *json_dump, *json_log, *ordered, *hc_port, *gcp_gae))

	tasks := createTasks(pcap_iface, timezone, directory, extension, filter, snaplen, interval, tcp_dump, json_dump, json_log, ordered, conntrack, gcp_gae)

	if len(tasks) == 0 {
		jlog(ERROR, &emptyTcpdumpJob, "no PCAP tasks available")
		os.Exit(1)
	}

	timeout := time.Duration(*duration) * time.Second
	jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("parsed timeout: %v", timeout))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// create empty job: used if CRON is not enabled
	job := &tcpdumpJob{Jid: uuid.Nil.String(), tasks: tasks}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		signal := <-signals
		jlog(INFO, job, fmt.Sprintf("signaled: %v", signal))
		cancel()
	}()

	// receives status of TCP listener termination: `true` means successful
	tcpStopChannel := make(chan bool, 1)

	// Skip scheduling, execute `tcpdump` immediately
	if !*use_cron {
		id := uuid.New().String()
		ctx = context.WithValue(ctx, pcap.PcapContextID, id)
		logName := fmt.Sprintf("projects/%s/pcaps/%s", os.Getenv("PROJECT_ID"), id)
		ctx = context.WithValue(ctx, pcap.PcapContextLogName, logName)
		// start the TCP listener for health checks
		go startTCPListener(ctx, hc_port, tcpStopChannel)
		start(ctx, timeout, job)
		return
	}

	// The `timezone` to be used when scheduling `tcpdump` cron jobs
	location, err := time.LoadLocation(*timezone)
	if err != nil {
		*timezone = "UTC"
		location = time.UTC
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("could not load timezone '%s': %v", *timezone, err))
	}
	jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("parsed timezone: %v", location))

	// Create a scheduler using the requested timezone.
	// no more than 1 packet capturing job should ever be executed.
	s, err := gocron.NewScheduler(
		gocron.WithLimitConcurrentJobs(1, gocron.LimitModeReschedule),
		gocron.WithLocation(location),
		gocron.WithGlobalJobOptions(
			gocron.WithTags(
				os.Getenv("PROJECT_ID"),
				os.Getenv("APP_SERVICE"),
				os.Getenv("GCP_REGION"),
				os.Getenv("APP_REVISION"),
				os.Getenv("INSTANCE_ID"),
			),
		),
	)
	if err != nil {
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("failed to create scheduler: %v", err))
		os.Exit(2)
	}

	// Use the provided `cron` expression ro schedule the packet capturing job
	j, err := s.NewJob(
		gocron.CronJob(fmt.Sprintf("TZ=%s %s", *timezone, *cron_exp), true),
		gocron.NewTask(tcpdump, timeout),
		gocron.WithName("tcpdump"),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithEventListeners(
			gocron.AfterJobRuns(afterTcpdump),
			gocron.BeforeJobRuns(beforeTcpdump),
		),
	)
	if err != nil {
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("failed to create scheduled job: %v", err))
		s.Shutdown()
		os.Exit(3)
	}

	jid.Store(j.ID())

	// redefine default `job` with the scheduled one
	job = &tcpdumpJob{
		ctx:   ctx,
		tasks: tasks,
		Jid:   j.ID().String(),
		Name:  j.Name(),
		Tags:  j.Tags(),
		j:     &j,
	}
	jobs.Store(j.ID(), job)
	jlog(INFO, job, "scheduled job")

	// Start the packet capturing scheduler
	s.Start()

	nextRun, _ := j.NextRun()
	jlog(INFO, job, fmt.Sprintf("next execution: %v", nextRun))

	// start the TCP listener for health checks
	go startTCPListener(ctx, hc_port, tcpStopChannel)

	// Block main goroutine until a signal is received
	<-ctx.Done()

	s.StopJobs()
	s.RemoveJob(j.ID())
	s.Shutdown()

	// wait for TCP listener to be terminated
	isTCPstopOK := <-tcpStopChannel
	if !isTCPstopOK {
		// signal unclean termination
		os.Exit(5)
	}
}
