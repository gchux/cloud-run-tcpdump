package transformer

import (
  "io"
  "fmt"
  "context"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

type PcapTranslator interface {
  translate(packet *gopacket.Packet) error
  next() fmt.Stringer 
  translateEthernetLayer(ctx context.Context, packet *layers.Ethernet, buffer fmt.Stringer)
}

type PcapTransformer struct {
  translator PcapTranslator
  output     string
  ctx        context.Context
  ich        chan<- concurrently.WorkFunction
  och        <-chan concurrently.OrderedOutput
}

type IPcapTransformer interface {
  Apply(packet *gopacket.Packet) error
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
    T.translateEthernetLayer(ctx, ethernetPacket, buffer)
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

func writePacket(ctx context.Context, writer io.Writer, out concurrently.OrderedOutput) {
  fmt.Fprintf(writer, "%s\n", out.Value)
}

func writePackets(ctx context.Context, i chan<- concurrently.WorkFunction, o <-chan concurrently.OrderedOutput, writers []io.Writer) {
  for {
    select {
    case out := <-o:
      for _, writer := range writers {
        go writePacket(ctx, writer, out)
      }
    case <-ctx.Done():
      close(i)
      return
    }
  }
}

func NewTransformer(ctx context.Context, writers []io.Writer, format *string) (IPcapTransformer, error) {

  translator, err := newTranslator(format)
  if err != nil {
    return nil, err
  }

  ich := make(chan concurrently.WorkFunction, 10)
  ochOpts := &concurrently.Options{PoolSize: 10, OutChannelBuffer: 10}
  och := concurrently.Process(ctx, ich, ochOpts)

  go writePackets(ctx, ich, och, writers)

  // same transformer, multiple strategies
  return &PcapTransformer{translator: translator, ctx: ctx, ich: ich, och: och}, nil
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

