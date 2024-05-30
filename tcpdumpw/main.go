package main

import (
  "fmt"
  "log"
  "time"
  "flag"
  "os"
  "os/exec"
  "context"
  _ "time/tzdata"

  "github.com/go-co-op/gocron/v2"
)

func tcpdump(timeout time.Duration, snaplen, secs int, dir , ext , filter string) error {

  tcpdump_bin, err := exec.LookPath("tcpdump")
  if err != nil {
    log.Println("[ERROR] - [tcpdumpw] - 'tcpdump' is not available")
    return fmt.Errorf("tcpdump is not available")
  } else {
    log.Printf("[INFO] - [tcpdumpw] - using 'tcpdump' bin: '%s'\n", tcpdump_bin)
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

  log.Printf("[INFO] - [tcpdumpw] - EXEC: %v\n", cmd.Args)
  if err := cmd.Run(); err != nil {
    log.Printf("[INFO] - [tcpdumpw] - stopped '%s' after %v\n", tcpdump_bin, timeout)
  }

  return nil
}

func main() {

  timezone  := flag.String("timezone",  "UTC",  "TimeZone to be used to schedule packet captures")
  use_cron  := flag.Bool("use_cron",    false,  "perform packet capture at specific intervals")
  cron_exp  := flag.String("cron_exp",  "",     "stardard cron expression; i/e: '1 * * * *'")
  duration  := flag.Int("timeout",      0,      "perform packet capture during this mount of seconds")
  snaplen   := flag.Int("snaplen",      0,      "bytes to be captured from each packet")
  filter    := flag.String("filter",    "",     "BPF filter to be used for capturing packets")
  extension := flag.String("extension", "pcap", "extension to be used for PCAP files")
  directory := flag.String("directory", "",     "directory where PCAP files will be stored")

  flag.Parse()

  log.Printf("[INFO] - [tcpdumpw] -  args[use_cron]: %v\n", *use_cron);
  log.Printf("[INFO] - [tcpdumpw] -  args[cron_exp]: %s\n", *cron_exp);
  log.Printf("[INFO] - [tcpdumpw] -  args[timezone]: %s\n", *timezone);
  log.Printf("[INFO] - [tcpdumpw] -   args[timeout]: %d\n", *duration);
  log.Printf("[INFO] - [tcpdumpw] - args[extension]: %s\n", *extension);
  log.Printf("[INFO] - [tcpdumpw] - args[directory]: %s\n", *directory);
  log.Printf("[INFO] - [tcpdumpw] -   args[snaplen]: %d\n", *snaplen);
  log.Printf("[INFO] - [tcpdumpw] -    args[filter]: %s\n", *filter);

  timeout := time.Duration(*duration) * time.Second
  log.Printf("[INFO] - [tcpdumpw] - parsed timeout: %v\n", timeout)

  // Skip scheduling, execute `tcpdump`
  if !*use_cron {
    tcpdump(timeout, *snaplen, *duration, *directory, *extension, *filter)
    return
  }

  // The `timezone` to be used when scheduling `tcpdump` cron jobs
  location, err := time.LoadLocation(*timezone)
  if err != nil {
    log.Printf("[ERROR] – could not load timezone '%s': %v\n", *timezone, err)
  }
  log.Printf("[INFO] - [tcpdumpw] - parsed timezone: %v\n", location)

  // Create a scheduler using the requested timezone.
  // no more than 1 packet capturing job should ever be executed.
  s, err := gocron.NewScheduler(
    gocron.WithLimitConcurrentJobs(1, gocron.LimitModeReschedule),
    gocron.WithLocation(location),
  )
  if err != nil {
    log.Printf("[ERROR] - failed to create scheduler: %v\n", err)
    return
  }

  // Use the provided `cron` expression ro schedule the packet capturing job
  j, err := s.NewJob(
    gocron.CronJob(*cron_exp, true),
    gocron.NewTask(tcpdump, timeout, *snaplen, *duration, *directory, *extension, *filter),
  )
  if err != nil {
    log.Printf("[ERROR] - [tcpdumpw] - failed to schedule packet capturing job: %v\n", err)
    return
  }

  log.Printf("[INFO] - [tcpdumpw] - scheduled tcpdump job_id: %s\n", j.ID())

  // Start the packet capturing scheduler
  s.Start()

  select{}
}
