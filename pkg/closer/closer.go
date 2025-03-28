package closer

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var fns []func() error

func init() {
	termSig := make(chan os.Signal, 1)
	signal.Notify(termSig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-termSig
		log.Println("Os signal:", s)

		wg := sync.WaitGroup{}
		wg.Add(len(fns))
		for _, fn := range fns {
			go func() {
				defer wg.Done()
				if err := fn(); err != nil {
					log.Printf("Closer error: %v", err)
				}
			}()
		}
		wg.Wait()
		os.Exit(1)
	}()
}

func Add(fn func() error) {
	fns = append(fns, fn)
}
