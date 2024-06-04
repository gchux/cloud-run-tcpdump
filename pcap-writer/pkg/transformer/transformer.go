package transformer

import (
  "os"
  "fmt"
  "context"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

type PcapTranslator interface{
  translate(packet *gopacket.Packet) error
  next() fmt.Stringer 
  translateEthernetLayer(packet *layers.Ethernet, buffer fmt.Stringer)
}

type PcapTransformer struct{
  translator PcapTranslator
  output     string
  ctx        context.Context
  ich        chan concurrently.WorkFunction
}

type IPcapTransformer interface{
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

func NewTransformer(ctx context.Context, format *string) (IPcapTransformer, error) {

  var translator PcapTranslator = newTranslator(format)

  if translator == nil {
    return nil, fmt.Errorf("not available: %s", *format)
  }

  ich := make(chan concurrently.WorkFunction, 10)
  och := concurrently.Process(ctx, ich, &concurrently.Options{PoolSize: 10, OutChannelBuffer: 10})

  go func(och <-chan concurrently.OrderedOutput) {
    for out := range och {
		  // ToDo: output file must be dynamically configured
		  fmt.Fprintf(os.Stdout, "%s\n", out.Value)
	  }
  }(och)

  // same transformer, multiple strategies
  return &PcapTransformer{translator: translator, ctx: ctx, ich: ich}, nil
}

func newTranslator(format *string) PcapTranslator {

  switch f := *format; f {
  case "json":
    return newJsonPcapTranslator()
  case "text":
    return newTextPcapTranslator()
  default:
    /* no-go */
  }

  return nil
}

