package pcap

import (
  "os"
  "fmt"
  "log"
  "errors"
  "strings"
  "context"
  "syscall"
  "os/exec"
  "sync/atomic"
  "path/filepath"

  ps "github.com/mitchellh/go-ps"
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

func (t *Tcpdump) kill(pid int) error {
  proc, err := os.FindProcess(pid)
  if err != nil {
    return err
  }
  return proc.Signal(syscall.SIGTERM)
}

func (t *Tcpdump) findAndKill() (int, error) {

  processes, err := ps.Processes()
  if err != nil {
    return 0, err
  }

  killCounter := 0
  for _, p := range processes {
    procId := p.Pid()
    execName := p.Executable()
    if execName == "tcpdump" {
      logger.Printf("killing %s(%d)\n", execName, procId)
      if err := t.kill(procId); err == nil {
        killCounter++
      }
    }
  }
  return killCounter, nil
}

func (t *Tcpdump) Start(ctx context.Context, _ []PcapWriter) error {

  // atomically activate the packet capture
  if !t.isActive.CompareAndSwap(false, true) {
    return fmt.Errorf("already started")
  }
  
  // check for orphaned executions before starting a new one
  // orphaned tcpdump executions should be exceedingly rare
  killedProcs, err := t.findAndKill()
  if err == nil && killedProcs > 0 {
    logger.Printf("killed %d processes", killedProcs)
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
    killErr := cmd.Process.Kill()
    logger.Printf("STOP: %v\n", cmdLine)
    t.isActive.Store(false)
    return errors.Join(err, killErr)
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
