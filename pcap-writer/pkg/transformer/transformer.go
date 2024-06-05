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
  translateEthernetLayer(packet *layers.Ethernet, buffer fmt.Stringer)
}

type PcapTransformer struct {
  translator PcapTranslator
  output     string
  ctx        context.Context
  ich        chan<- concurrently.WorkFunction
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

func NewTransformer(ctx context.Context, writer io.Writer, format *string) (IPcapTransformer, error) {

  translator, err := newTranslator(format)
  if err != nil {
    return nil, err
  }

  ich := make(chan concurrently.WorkFunction, 10)
  ochOpts := &concurrently.Options{PoolSize: 10, OutChannelBuffer: 10}
  och := concurrently.Process(ctx, ich, ochOpts)

  go func(ctx context.Context, i chan concurrently.WorkFunction, o <-chan concurrently.OrderedOutput, w io.Writer) {
    for {
      select {
      case out := <-o:
        fmt.Fprintf(w, "%s\n", out.Value)
      case <-ctx.Done():
        close(i)
        return
      }
    }
  }(ctx, ich, och, writer)

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

