package main

import (
  "fmt"
  "time"
  "flag"
  "strings"
  "os"
  "os/exec"
  "context"
  "sync/atomic"
  "encoding/json"
  _ "time/tzdata"

  "github.com/lrita/cmap"
  "github.com/google/uuid"
  "github.com/go-co-op/gocron/v2"
)

var sidecar string = os.Getenv("RUN_SIDECAR")
var module  string = os.Getenv("PROC_NAME")

var jid, xid atomic.Value

type tcpdumpJob struct {
  j    *gocron.Job `json:"-"`
  Xid  string      `json:"xid,omitempty"`
  Jid  string      `json:"jid,omitempty"`
  Name string      `json:"name,omitempty"`
  Tags []string    `json:"-"`
}

var jobs cmap.Map[uuid.UUID, *tcpdumpJob]

type jLogLevel string
const (
  INFO  jLogLevel = "INFO"
  ERROR jLogLevel = "ERROR"
)

type jLogEntry struct {
  Severity jLogLevel  `json:"severity"`
  Message  string     `json:"message"`
  Sidecar  string     `json:"sidecar"`
  Module   string     `json:"module"`
  Job      tcpdumpJob `json:"job,omitempty"`
  Tags     []string   `json:"tags,omitempty"` 
}

var empty_tcpdump_job = tcpdumpJob{Jid: uuid.Nil.String()}

func jlog(severity jLogLevel, job *tcpdumpJob, message string) {

  j := *job
  j.Xid = xid.Load().(uuid.UUID).String()

  entry := &jLogEntry{ 
    Severity: severity,
    Message: message,
    Sidecar: sidecar,
    Module: module,
    Job: j,
    Tags: j.Tags,
  }
  
  jEntry, _ := json.Marshal(entry)
  fmt.Println(string(jEntry))
}

func after_tcpdump(id uuid.UUID, name string) {
  if job, ok := jobs.Load(id); ok {
    jlog(INFO, job, "execution complete")
    j := *job.j
    nextRun, _ := j.NextRun()
    jlog(INFO, job, fmt.Sprintf("next execution: %v", nextRun))
  }
  xid.Store(uuid.Nil) // reset execution id
}

func before_tcpdump(id uuid.UUID, name string) {
  if job, ok := jobs.Load(id); ok {
    jlog(INFO, job, "execution started")
  }
  xid.Store(uuid.New())
}

func tcpdump(timeout time.Duration, snaplen, secs int, dir , ext , filter string) error {

  job_id := jid.Load().(uuid.UUID)

  var job *tcpdumpJob
  var ok bool
  if job, ok = jobs.Load(job_id); !ok {
    message := fmt.Sprintf("job[id:%s] not found", job_id)
    jlog(ERROR, &empty_tcpdump_job, message)
    return fmt.Errorf(message)
  }

  tcpdump_bin, err := exec.LookPath("tcpdump")
  
  if err != nil {
    jlog(ERROR, job, "tcpdump is not available")
    return fmt.Errorf("tcpdump is not available")
  }

  ctx := context.Background()

  if timeout > 0 * time.Second {
    ctx, _ = context.WithTimeout(ctx, timeout)
  }

  // tcpdump -n -s ${PCAP_SNAPLEN} -i any -w ${PCAP_FILE}_%Y%m%d_%H%M%S.${PCAP_EXT} -Z root -G ${PCAP_SECS} "${PCAP_FILTER}"
  cmd := exec.CommandContext(ctx, tcpdump_bin,
    "-n", "-i", "any", "-Z", "root", 
    "-s", fmt.Sprintf("%d", snaplen),
    "-w", fmt.Sprintf("%s/part_%%Y%%m%%d_%%H%%M-%%S.%s", dir, ext),
    "-G", fmt.Sprintf("%d", secs),
    fmt.Sprintf("%s", filter),
  )

  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr

  cmd_line := strings.Join(cmd.Args[:], " ")
  jlog(INFO, job, fmt.Sprintf("EXEC: %v", cmd_line))
  if err := cmd.Run(); err != nil {
    jlog(INFO, job, fmt.Sprintf("STOP: %v", cmd_line))
  }

  return nil
}

func main() {

  timezone  := flag.String("timezone",  "UTC",  "TimeZone to be used to schedule packet captures")
  use_cron  := flag.Bool("use_cron",    false,  "perform packet capture at specific intervals")
  cron_exp  := flag.String("cron_exp",  "",     "stardard cron expression; i/e: '1 * * * *'")
  duration  := flag.Int("timeout",      0,      "perform packet capture during this mount of seconds")
  rotate_s  := flag.Int("rotate_s",     60,     "seconds after which tcpdump rotates PCAP files")
  snaplen   := flag.Int("snaplen",      0,      "bytes to be captured from each packet")
  filter    := flag.String("filter",    "",     "BPF filter to be used for capturing packets")
  extension := flag.String("extension", "pcap", "extension to be used for PCAP files")
  directory := flag.String("directory", "",     "directory where PCAP files will be stored")

  flag.Parse()

  jid.Store(uuid.Nil)
  xid.Store(uuid.Nil)

  jlog(INFO, &empty_tcpdump_job,
    fmt.Sprintf("args[use_cron:%t|cron_exp:%s|timezone:%s|timeout:%d|extension:%s|directory:%s|snaplen:%d|filter:%s|rotate_s:%d]", 
    *use_cron, *cron_exp, *timezone, *duration, *extension, *directory, *snaplen, *filter, *rotate_s))

  timeout := time.Duration(*duration) * time.Second
  jlog(INFO, &empty_tcpdump_job, fmt.Sprintf("parsed timeout: %v", timeout))

  // Skip scheduling, execute `tcpdump`
  if !*use_cron {
    tcpdump(timeout, *snaplen, *rotate_s, *directory, *extension, *filter)
    return
  }

  // The `timezone` to be used when scheduling `tcpdump` cron jobs
  location, err := time.LoadLocation(*timezone)
  if err != nil {
    jlog(ERROR, &empty_tcpdump_job, fmt.Sprintf("could not load timezone '%s': %v", *timezone, err))
  }
  jlog(INFO, &empty_tcpdump_job, fmt.Sprintf("parsed timezone: %v", location))

  // Create a scheduler using the requested timezone.
  // no more than 1 packet capturing job should ever be executed.
  s, err := gocron.NewScheduler(
    gocron.WithLimitConcurrentJobs(1, gocron.LimitModeReschedule),
    gocron.WithLocation(location),
    gocron.WithGlobalJobOptions(
      gocron.WithTags(
        os.Getenv("PROJECT_ID"),
        os.Getenv("RUN_SERVICE"),
        os.Getenv("GCP_REGION"),
        os.Getenv("RUN_REVISION"),
        os.Getenv("INSTANCE_ID"),
      ),
    ),
  )
  if err != nil {
    jlog(ERROR, &empty_tcpdump_job, fmt.Sprintf("failed to create scheduler: %v", err))
    return
  }

  // Use the provided `cron` expression ro schedule the packet capturing job
  j, err := s.NewJob(
    gocron.CronJob(*cron_exp, true),
    gocron.NewTask(tcpdump, timeout, *snaplen, *rotate_s, *directory, *extension, *filter),
    gocron.WithName("tcpdump"),
    gocron.WithSingletonMode(gocron.LimitModeReschedule),
    gocron.WithEventListeners(
      gocron.AfterJobRuns(after_tcpdump),
      gocron.BeforeJobRuns(before_tcpdump),
    ),
  )
  if err != nil {
    jlog(ERROR, &empty_tcpdump_job, fmt.Sprintf("failed to create scheduled job: %v", err))
    return
  }

  jid.Store(j.ID())

  job := &tcpdumpJob{Jid: j.ID().String(), Name: j.Name(), Tags: j.Tags(), j: &j}
  jobs.Store(j.ID(), job)
  jlog(INFO, job, "scheduled job")

  // Start the packet capturing scheduler
  s.Start()
  
  nextRun, _ := j.NextRun()
  jlog(INFO, job, fmt.Sprintf("next execution: %v", nextRun))

  // Block main goroutine forever.
  <-make(chan struct{})
}
