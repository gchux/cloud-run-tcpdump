package transformer

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/panjf2000/ants/v2"
	concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

type PcapTranslator interface {
	translate(packet *gopacket.Packet) error
	next() fmt.Stringer
	translateEthernetLayer(context.Context, *int64, *layers.Ethernet, fmt.Stringer)
}

type PcapTransformer struct {
	ctx            context.Context
	ich            chan<- concurrently.WorkFunction
	och            <-chan concurrently.OrderedOutput
	translator     PcapTranslator
	translatorPool *ants.PoolWithFunc
	writerPool     *ants.MultiPoolWithFunc
	writers        []io.Writer
	writeQueues    []chan *fmt.Stringer
	wg             sync.WaitGroup
	preserveOrder  bool
}

type IPcapTransformer interface {
	WaitDone()
	Apply(context.Context, *gopacket.Packet, *int64) error
}

// Create a type based on your input to the work function
type pcapWorker struct {
	serial     *int64
	packet     *gopacket.Packet
	translator PcapTranslator
}

type pcapWriteTask struct {
	ctx         context.Context
	writer      io.Writer
	translation *fmt.Stringer
}

func (w pcapWorker) translateEthernetLayer(ctx context.Context, buffer *fmt.Stringer) {
	ethernetLayer := (*w.packet).Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		w.translator.translateEthernetLayer(ctx, w.serial, ethernetPacket, *buffer)
	}
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w pcapWorker) Run(ctx context.Context) interface{} {
	buffer := w.translator.next()

	w.translateEthernetLayer(ctx, &buffer)

	// translate more layers

	return &buffer
}

func (t *PcapTransformer) translatePacket(ctx context.Context, task *pcapWorker) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case t.ich <- task:
		t.wg.Add(len(t.writers))
	}
	return nil
}

func (t *PcapTransformer) produceTranslations(ctx context.Context) {
	for translation := range t.och {
		// consume translations and push them into translations consumers
		for _, translations := range t.writeQueues {
			// if any of the consumers' buffers is full,
			// the saturated/slower one will block and delay iterations.
			// Blocking is more likely when `preserveOrder` is enabled; however,
			// if `preserveOrder` is disabled, non written translations are dropped after 5s.
			translations <- translation.Value.(*fmt.Stringer)
		}
	}
}

func (t *PcapTransformer) writeTranslation(ctx context.Context, task *pcapWriteTask) {
	// consume translations – flush them into writers
	io.WriteString(task.writer, fmt.Sprintf("%s\n", *task.translation))
	t.wg.Done()
}

func (t *PcapTransformer) consumeTranslations(ctx context.Context, index int) {
	var translations chan *fmt.Stringer = t.writeQueues[index]
	var writer io.Writer = t.writers[index]

	for translation := range translations {

		task := &pcapWriteTask{
			ctx:         ctx,
			writer:      writer,
			translation: translation,
		}

		if t.preserveOrder {
			t.writeTranslation(ctx, task)
		} else {
			t.writerPool.Invoke(task)
		}

	}
}

func (t *PcapTransformer) waitForContextDone(ctx context.Context) error {
	select {
	case <-ctx.Done():
		close(t.ich)
		return ctx.Err()
	}
	return nil
}

// returns when all packets have been transformed and written
func (t *PcapTransformer) WaitDone() {
	t.wg.Wait() // wait for all translations to be written
	for _, writeQueue := range t.writeQueues {
		close(writeQueue) // close writer channels
	}
	// if order is not enforced, there are not worker pools to be stopped
	if !t.preserveOrder {
		t.translatorPool.Release()
		t.writerPool.ReleaseTimeout(0 * time.Second)
	}
}

func (t *PcapTransformer) Apply(ctx context.Context, packet *gopacket.Packet, serial *int64) error {
	// process/translate packets concurrently in order to
	// avoid blocking `gopacket` captured packets channel.
	// Order of gorouting execution is not guaranteed, which means
	// that packets will be consumed/written in non-deterministic order.
	// `serial` is aviailable to be used for sorting PCAP files.

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	task := &pcapWorker{
		serial:     serial,
		packet:     packet,
		translator: t.translator,
	}

	if t.preserveOrder {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t.ich <- task:
			t.wg.Add(len(t.writers))
		}
		return nil
	}

	t.translatorPool.Invoke(task)
	return nil
}

func translatePacket(ctx context.Context, transformer *PcapTransformer, worker interface{}) {
	transformer.translatePacket(ctx, worker.(*pcapWorker))
}

func writeTranslation(ctx context.Context, transformer *PcapTransformer, task interface{}) {
	transformer.writeTranslation(ctx, task.(*pcapWriteTask))
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

func provideWorkerPools(ctx context.Context, transformer *PcapTransformer, numWriters int) {
	poolOpts := ants.Options{
		PreAlloc:       true,
		Nonblocking:    false,
		ExpiryDuration: 5 * time.Second,
	}
	poolOpt := ants.WithOptions(poolOpts)

	translatorPoolFn := func(i interface{}) {
		translatePacket(ctx, transformer, i)
	}
	translatorPool, _ := ants.NewPoolWithFunc(10, translatorPoolFn, poolOpt)
	transformer.translatorPool = translatorPool

	writerPoolFn := func(i interface{}) {
		writeTranslation(ctx, transformer, i)
	}
	writerPool, _ := ants.NewMultiPoolWithFunc(numWriters, 10*numWriters, writerPoolFn, ants.LeastTasks, poolOpt)
	transformer.writerPool = writerPool
}

// transformers get instances of `io.Writer` instead of `pcap.PcapWriter` to prevent closing.
func newTransformer(ctx context.Context, writers []io.Writer, format *string, preserveOrder bool) (IPcapTransformer, error) {
	translator, err := newTranslator(format)
	if err != nil {
		return nil, err
	}

	ich := make(chan concurrently.WorkFunction, 10)
	ochOpts := &concurrently.Options{PoolSize: 10, OutChannelBuffer: 10}
	och := concurrently.Process(context.Background(), ich, ochOpts)

	numWriters := len(writers)
	// not using `io.MultiWriter` as it writes to all writers sequentially
	writeQueues := make([]chan *fmt.Stringer, numWriters)
	for i := range writers {
		writeQueues[i] = make(chan *fmt.Stringer, 10)
	}

	var wg sync.WaitGroup

	// same transformer, multiple strategies
	// via multiple translator implementations
	transformer := &PcapTransformer{
		wg:            wg,
		ctx:           ctx,
		ich:           ich,
		och:           och,
		translator:    translator,
		writers:       writers,
		writeQueues:   writeQueues,
		preserveOrder: preserveOrder,
	}

	// `preserveOrder==true` causes writes to be sequential and blocking per writer.
	// `preserveOrder==true` does not cause `transformer.Apply` to block.
	if !preserveOrder {
		provideWorkerPools(ctx, transformer, numWriters)
	}

	go transformer.produceTranslations(ctx)
	// spawn consumers for all writers
	for i := range writeQueues {
		go transformer.consumeTranslations(ctx, i)
	}

	go transformer.waitForContextDone(ctx)

	return transformer, nil
}

func NewOrderedTransformer(ctx context.Context, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, writers, format, true /* preserveOrder */)
}

func NewTransformer(ctx context.Context, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, writers, format, false /* preserveOrder */)
}
