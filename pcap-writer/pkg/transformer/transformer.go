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
	translate(*gopacket.Packet) error
	next(context.Context, *int64) fmt.Stringer
	translateEthernetLayer(context.Context, *layers.Ethernet, fmt.Stringer)
	translateIPLayer(context.Context, *layers.IPv4, fmt.Stringer)
	translateTCPLayer(context.Context, *layers.TCP, fmt.Stringer)
}

type PcapTransformer struct {
	ctx            context.Context
	ich            chan concurrently.WorkFunction
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

func (w pcapWorker) pkt() gopacket.Packet {
	return *w.packet
}

func (w pcapWorker) asLayer(layer gopacket.LayerType) gopacket.Layer {
	return w.pkt().Layer(layer)
}

func (w pcapWorker) translateEthernetLayer(ctx context.Context, buffer *fmt.Stringer) {
	ethernetLayer := w.asLayer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		w.translator.translateEthernetLayer(ctx, ethernetPacket, *buffer)
	}
}

func (w pcapWorker) translateIPLayer(ctx context.Context, buffer *fmt.Stringer) {
	ipLayer := w.asLayer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		w.translator.translateIPLayer(ctx, ipPacket, *buffer)
	}
}

func (w pcapWorker) translateTCPLayer(ctx context.Context, buffer *fmt.Stringer) {
	tcpLayer := w.asLayer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		w.translator.translateTCPLayer(ctx, tcpPacket, *buffer)
	}
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w pcapWorker) Run(ctx context.Context) interface{} {
	buffer := w.translator.next(ctx, w.serial)

	// [TODO]: translate layers concurrently
	w.translateEthernetLayer(ctx, &buffer)
	w.translateIPLayer(ctx, &buffer)
	w.translateTCPLayer(ctx, &buffer)

	// translate more layers

	return &buffer
}

func (t *PcapTransformer) writeTranslation(ctx context.Context, task *pcapWriteTask) {
	// consume translations – flush them into writers
	io.WriteString(task.writer, fmt.Sprintf("%s\n", *task.translation))
	t.wg.Done()
}

func (t *PcapTransformer) publishTranslation(ctx context.Context, translation *fmt.Stringer) {
	for _, translations := range t.writeQueues {
		// if any of the consumers' buffers is full,
		// the saturated/slower one will block and delay iterations.
		// Blocking is more likely when `preserveOrder` is enabled.
		translations <- translation
	}
}

func (t *PcapTransformer) produceTranslation(ctx context.Context, task *pcapWorker) error {
	t.publishTranslation(ctx, task.Run(ctx).(*fmt.Stringer))
	return nil
}

func (t *PcapTransformer) produceTranslations(ctx context.Context) {
	// translations are made available in the enqueued order
	for translation := range t.och {
		// consume translations and push them into translations consumers
		t.publishTranslation(ctx, translation.Value.(*fmt.Stringer))
	}
}

func (t *PcapTransformer) consumeTranslations(ctx context.Context, index int) {
	var writer io.Writer = t.writers[index]

	for translation := range t.writeQueues[index] {

		task := &pcapWriteTask{
			ctx:         ctx,
			writer:      writer,
			translation: translation,
		}

		if t.preserveOrder {
			// this is mostly blocking
			t.writeTranslation(ctx, task)
		} else {
			// this is mostly non-blocking
			t.writerPool.Invoke(task)
		}
	}
}

func (t *PcapTransformer) waitForContextDone(ctx context.Context) {
	select {
	case <-ctx.Done():
		close(t.ich)
	}
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
		t.writerPool.ReleaseTimeout(0)
	}
}

func (t *PcapTransformer) Apply(ctx context.Context, packet *gopacket.Packet, serial *int64) error {
	// It is assumed that packets will be produced faster than translations.
	// process/translate packets concurrently in order to avoid blocking `gopacket` packets channel.

	task := &pcapWorker{
		serial:     serial,
		packet:     packet,
		translator: t.translator,
	}

	t.wg.Add(len(t.writers))

	// If ordered output is enabled, enqueue translation workers in packet capture order;
	// this will introduce some level of contention as the translation Q starts to fill (saturation):
	// if the next packet to arrive finds a full Q, this method will block until slots are available.
	// The degree of contention is proportial to the Q capacity times translation latency.
	// Order should only be used for not network intersive workloads.
	if t.preserveOrder {
		t.ich <- task
		return nil
	}

	// if ordered output is disabled, translate packets concurrently via translator pool.
	// Order of gorouting execution is not guaranteed, which means
	// that packets will be consumed/written in non-deterministic order.
	// `serial` is aviailable to be used for sorting PCAP files.
	t.translatorPool.Invoke(task)
	return nil
}

func translatePacket(ctx context.Context, transformer *PcapTransformer, worker interface{}) {
	transformer.produceTranslation(ctx, worker.(*pcapWorker))
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

// if preserving packet capture order is not required, translations may be done concurrently
// concurrently translating packets means that translations are not enqueded in packet capture order.
// Similarly, sinking translations into files can be safely done concurrently ( in whatever order goroutines are scheduled )
func provideWorkerPools(ctx context.Context, transformer *PcapTransformer, numWriters int) {
	poolOpts := ants.Options{
		PreAlloc:       true,
		Nonblocking:    false,
		ExpiryDuration: 5 * time.Second,
	}
	poolOpt := ants.WithOptions(poolOpts)

	poolSize := 10 * numWriters

	translatorPoolFn := func(i interface{}) {
		translatePacket(ctx, transformer, i)
	}
	translatorPool, _ := ants.NewPoolWithFunc(poolSize, translatorPoolFn, poolOpt)
	transformer.translatorPool = translatorPool

	writerPoolFn := func(i interface{}) {
		writeTranslation(ctx, transformer, i)
	}
	writerPool, _ := ants.NewMultiPoolWithFunc(numWriters, poolSize, writerPoolFn, ants.LeastTasks, poolOpt)
	transformer.writerPool = writerPool
}

func provideConcurrentQueue(ctx context.Context, transformer *PcapTransformer, numWriters int) {
	queueSize := 20 * numWriters

	ochOpts := &concurrently.Options{
		PoolSize:         queueSize,
		OutChannelBuffer: queueSize,
	}

	transformer.ich = make(chan concurrently.WorkFunction, queueSize)
	transformer.och = concurrently.Process(ctx, transformer.ich, ochOpts)
}

// transformers get instances of `io.Writer` instead of `pcap.PcapWriter` to prevent closing.
func newTransformer(ctx context.Context, writers []io.Writer, format *string, preserveOrder bool) (IPcapTransformer, error) {
	translator, err := newTranslator(format)
	if err != nil {
		return nil, err
	}

	numWriters := len(writers)
	// not using `io.MultiWriter` as it writes to all writers sequentially
	writeQueues := make([]chan *fmt.Stringer, numWriters)
	for i := range writers {
		writeQueues[i] = make(chan *fmt.Stringer, 10*numWriters)
	}

	var wg sync.WaitGroup

	// same transformer, multiple strategies
	// via multiple translator implementations
	transformer := &PcapTransformer{
		wg:            wg,
		ctx:           ctx,
		translator:    translator,
		writers:       writers,
		writeQueues:   writeQueues,
		preserveOrder: preserveOrder,
	}

	// `preserveOrder==true` causes writes to be sequential and blocking per `io.Writer`.
	// `preserveOrder==true` although blocking at writting, does not cause `transformer.Apply` to block.
	if preserveOrder {
		provideConcurrentQueue(ctx, transformer, numWriters)
		go transformer.waitForContextDone(ctx)
	} else {
		provideWorkerPools(ctx, transformer, numWriters)
	}

	go transformer.produceTranslations(ctx)
	// spawn consumers for all `io.Writer`s
	// 1 consumer goroutine per `io.Writer`
	for i := range writeQueues {
		go transformer.consumeTranslations(ctx, i)
	}

	return transformer, nil
}

func NewOrderedTransformer(ctx context.Context, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, writers, format, true /* preserveOrder */)
}

func NewTransformer(ctx context.Context, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, writers, format, false /* preserveOrder */)
}
