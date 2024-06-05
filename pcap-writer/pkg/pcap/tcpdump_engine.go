package pcap

import (
  "os"
  "fmt"
  "log"
  "strings"
  "context"
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

func (t *Tcpdump) Start(ctx context.Context, _ PcapWriter) error {

  // atomically activate the packet capture
  if !t.isActive.CompareAndSwap(false, true) {
    return fmt.Errorf("already started")
  }

  tcpdumpBin, err := exec.LookPath("tcpdump")
  
  if err != nil {
    logger.Fatalln("tcpdump is not available")
    t.isActive.Store(false)
    return fmt.Errorf("tcpdump is unavailable")
  }

  cfg := t.config

  args := t.buildArgs(ctx)

  cmd := exec.CommandContext(ctx, tcpdumpBin, args...)

  if cfg.Output == "stdout" {
    cmd.Stdout = os.Stdout
  }
  cmd.Stderr = os.Stderr

  cmdLine := strings.Join(cmd.Args[:], " ")
  logger.Printf("EXEC: %v\n", cmdLine)
  if err := cmd.Run(); err != nil {
    logger.Printf("STOP: %v\n", cmdLine)
    return err
  }

  return nil
}

func NewTcpdump(config *PcapConfig) (PcapEngine, error) {
  
  var isActive atomic.Bool
  isActive.Store(false)

  tcpdump := Tcpdump{config: config, isActive: isActive}
  return &tcpdump, nil
} 
