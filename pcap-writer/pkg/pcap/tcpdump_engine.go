package pcap

import (
  "os"
  "fmt"
  "log"
  "strings"
  "context"
  "syscall"
  "os/exec"
  "sync/atomic"
  "path/filepath"
)

var logger = log.New(os.Stderr, "[tcpdump] - ", log.LstdFlags)

func (t *Tcpdump) IsActive() bool {
  return t.isActive.Load()
}

func (t *Tcpdump) buildArgs(ctx context.Context) []string {

  cfg  := t.config

  args := []string{"-n", "-Z", "root", "-i", cfg.Iface, "-s", fmt.Sprintf("%d", cfg.Snaplen)}

  if cfg.Output != "stdout" {
    directory := filepath.Dir(cfg.Output)
    template  := filepath.Base(cfg.Output)
    fileNameTemplate := fmt.Sprintf("%s/%s.%s", directory, template, cfg.Extension)
    args = append(args, "-w", fileNameTemplate)
  } 

  if cfg.Interval > 0 {
    args = append(args, "-G", fmt.Sprintf("%d", cfg.Interval))
  }

  if cfg.Filter != "" {
    args = append(args, fmt.Sprintf("%s", cfg.Filter))
  }

  return args
}

func (t *Tcpdump) Start(ctx context.Context, _ []PcapWriter) error {

  // atomically activate the packet capture
  if !t.isActive.CompareAndSwap(false, true) {
    return fmt.Errorf("already started")
  }

  cfg := t.config

  args := t.buildArgs(ctx)

  cmd := exec.CommandContext(ctx, t.tcpdump, args...)

  // prevent child process from hijacking signals
  cmd.SysProcAttr = &syscall.SysProcAttr{
    Setpgid: true, Pgid: 0,
  }

  if cfg.Output == "stdout" {
    cmd.Stdout = os.Stdout
  }
  cmd.Stderr = os.Stderr

  cmdLine := strings.Join(cmd.Args[:], " ")
  logger.Printf("EXEC: %v\n", cmdLine)
  if err := cmd.Run(); err != nil {
    cmd.Process.Kill()
    logger.Printf("STOP: %v\n", cmdLine)
    t.isActive.Store(false)
    return err
  }

  t.isActive.Store(false)

  return nil
}

func NewTcpdump(config *PcapConfig) (PcapEngine, error) {
  
  tcpdumpBin, err := exec.LookPath("tcpdump")
  if err != nil {
    return nil, fmt.Errorf("tcpdump is unavailable")
  }

  var isActive atomic.Bool
  isActive.Store(false)

  tcpdump := Tcpdump{config: config, tcpdump: tcpdumpBin, isActive: isActive}
  return &tcpdump, nil
} 
