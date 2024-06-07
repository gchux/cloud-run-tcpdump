package transformer

import (
	"context"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

type PcapTranslator interface {
	translate(packet *gopacket.Packet) error
	next() fmt.Stringer
	translateEthernetLayer(context.Context, *int64, *layers.Ethernet, fmt.Stringer)
}

type PcapTransformer struct {
	translator  PcapTranslator
	ctx         context.Context
	ich         chan<- concurrently.WorkFunction
	och         <-chan concurrently.OrderedOutput
	writers     []io.Writer
	writeQueues []chan *concurrently.OrderedOutput
}

type IPcapTransformer interface {
	Apply(context.Context, *gopacket.Packet, *int64) error
}

// Create a type based on your input to the work function
type pcapWorker struct {
	serial     *int64
	packet     *gopacket.Packet
	translator PcapTranslator
}

func (w pcapWorker) translateEthernetLayer(ctx context.Context, buffer fmt.Stringer) {
	ethernetLayer := (*w.packet).Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		w.translator.translateEthernetLayer(ctx, w.serial, ethernetPacket, buffer)
	}
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w pcapWorker) Run(ctx context.Context) interface{} {
	buffer := w.translator.next()

	w.translateEthernetLayer(ctx, buffer)

	// translate more layers

	return buffer
}

func (t *PcapTransformer) translatePacket(ctx context.Context, packet *gopacket.Packet, serial *int64) {
	t.ich <- &pcapWorker{serial: serial, packet: packet, translator: t.translator}
}

func (t *PcapTransformer) Apply(ctx context.Context, packet *gopacket.Packet, serial *int64) error {
	// process/translate packets concurrently
	// avoid blocking `gopacket` captured packets channel.
	// This approach will produce 1 goroutine per packet.
	// Order of gorouting execution is not guaranteed, which means
	// that packets will be consumed/written in non-deterministic order.
	// `serial` is aviailable to be used for sorting PCAP files.
	go t.translatePacket(ctx, packet, serial)
	return nil
}

func (t *PcapTransformer) produceTranslations(ctx context.Context) {
	for {
		select {
		case translation := <-t.och:
			// consume translations and push them into translations consumers
			for _, translations := range t.writeQueues {
				// if any of the consumers' buffers is full,
				// the saturated one will block next iterations.
				// Consumer channels must -ideally- not block.
				translations <- &translation
			}
		case <-ctx.Done():
			close(t.ich)
			return
		}
	}
}

func (t *PcapTransformer) writeTranslation(ctx context.Context, writer io.Writer, translation *concurrently.OrderedOutput) {
	// consume translations – flush them into writers
	// `fmt.Fprintf(writer, ...)` is extraordinarily thread unsafe
	io.WriteString(writer, fmt.Sprintf("%s\n", translation.Value))
}

func (t *PcapTransformer) consumeTranslations(ctx context.Context, index int) {
	var translations chan *concurrently.OrderedOutput = t.writeQueues[index]
	var writer io.Writer = t.writers[index]
	for {
		select {
		case translation := <-translations:
			// consumer channels must not block
			go t.writeTranslation(ctx, writer, translation)
		case <-ctx.Done():
			close(translations)
			return
		}
	}
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

// transformers get instances of `io.Writer` instead of `pcap.PcapWriter` to prevent closing.
func NewTransformer(ctx context.Context, writers []io.Writer, format *string) (IPcapTransformer, error) {
	translator, err := newTranslator(format)
	if err != nil {
		return nil, err
	}

	ich := make(chan concurrently.WorkFunction, 10)
	ochOpts := &concurrently.Options{PoolSize: 10, OutChannelBuffer: 10}
	och := concurrently.Process(ctx, ich, ochOpts)

	// not using `io.MultiWriter` as it writes to all writers sequentially
	writeQueues := make([]chan *concurrently.OrderedOutput, len(writers))
	for i := range writers {
		writeQueues[i] = make(chan *concurrently.OrderedOutput, 10)
	}

	// same transformer, multiple strategies
	// via multiple translator implementations
	transformer := &PcapTransformer{
		ctx:         ctx,
		ich:         ich,
		och:         och,
		translator:  translator,
		writers:     writers,
		writeQueues: writeQueues,
	}

	go transformer.produceTranslations(ctx)
	// spawn consumers for all writers
	for i := range writeQueues {
		go transformer.consumeTranslations(ctx, i)
	}

	return transformer, nil
}
