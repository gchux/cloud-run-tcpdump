package transformer

import (
  "os"
  "io"
  "fmt"
  "bufio"
  "context"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

type PcapTranslator interface {
  translate(packet *gopacket.Packet) error
  next() fmt.Stringer 
  translateEthernetLayer(packet *layers.Ethernet, buffer fmt.Stringer)
}

type PcapTransformer struct {
  translator PcapTranslator
  output     string
  ctx        context.Context
  ich        chan concurrently.WorkFunction
}

type IPcapTransformer interface {
  Apply(packet *gopacket.Packet) error
}

type pcapWriter struct { // pcapStreamProvider
  targetFile *os.File
  buffered   bool
  closeable  bool
}

// Create a type based on your input to the work function
type pcapWorker struct {
  p *gopacket.Packet
  t PcapTranslator
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (p pcapWorker) Run(ctx context.Context) interface{} {

  T := p.t
  P := *p.p
 
  buffer := T.next()

  ethernetLayer := P.Layer(layers.LayerTypeEthernet)
  if ethernetLayer != nil {
    ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
    T.translateEthernetLayer(ethernetPacket, buffer)
  }
  
  return buffer.String()
}

func (t *PcapTransformer) Apply(packet *gopacket.Packet) error {
  
  // process packets concurrently
  go func(P *gopacket.Packet, T PcapTranslator) {
    t.ich <- &pcapWorker{p: P, t: T}
  }(packet, t.translator)

  // translate more layers

  return nil
}

func getPcapWriter(output *string) *pcapWriter {

  outFile := *output

  if outFile == "stdout" {
    return &pcapWriter{targetFile: os.Stdout, buffered: false, closeable: false}
  } else if outFile == "stderr" {
    return &pcapWriter{targetFile: os.Stderr, buffered: false, closeable: false}
  }

  targetFile, err := os.Create(outFile)
  if err != nil {
    return &pcapWriter{targetFile: os.Stdout, buffered: false, closeable: false}
  }

  return &pcapWriter{targetFile: targetFile, buffered: true, closeable: true}
}

func NewTransformer(ctx context.Context, output, format *string) (IPcapTransformer, error) {

  translator, err := newTranslator(format)
  if err != nil {
    return nil, err
  }

  ich := make(chan concurrently.WorkFunction, 10)
  ochOpts := &concurrently.Options{PoolSize: 10, OutChannelBuffer: 10}
  och := concurrently.Process(ctx, ich, ochOpts)

  stream := getPcapWriter(output)
  go func(och <-chan concurrently.OrderedOutput, stream *pcapWriter) {
    var w io.Writer = stream.targetFile
    if stream.buffered {
      w = bufio.NewWriter(stream.targetFile)
    }
    for out := range och {
      // [ToDo]:  @gchux
      // 1. enable PCAP file rotation after x amout of secs
      // 2. stream should be a provider, not a concrete type
      //    2.1 provider should only return new files for non std[out|err]
      //    2.2 provider should be passed as an `interface` instead of a `string`
      //        2.2.1 `PcapTransformer` must not be responsible for files rotation
      fmt.Fprintf(w, "%s\n", out.Value)
    }
    // pcapStreamProvider should flush and close on `rotate()`
    if stream.buffered {
      w.(*bufio.Writer).Flush()
    }
    if stream.closeable {
      stream.targetFile.Close()
    }
  }(och, stream)

  // same transformer, multiple strategies
  return &PcapTransformer{translator: translator, ctx: ctx, ich: ich}, nil
}

func newTranslator(format *string) (PcapTranslator, error) {

  switch f := *format; f {
  case "json":
    return newJsonPcapTranslator(), nil
  case "text":
    return newTextPcapTranslator(), nil
  default:
    /* no-go */
  }

  return nil, fmt.Errorf("translator unavailable: %s", *format)
}

