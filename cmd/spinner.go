package cmd

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// spinner renders an animated status line on a terminal. It writes to stderr so
// it never pollutes stdout (e.g. `scan --format json` or piped `list` output),
// and it disables itself entirely when stderr is not a TTY.
type spinner struct {
	out     *os.File
	enabled bool

	mu     sync.Mutex
	msg    string
	stopCh chan struct{}
	doneCh chan struct{}
}

var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

func newSpinner(out *os.File, msg string) *spinner {
	return &spinner{out: out, msg: msg, enabled: isTerminal(out)}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (s *spinner) Start() {
	if !s.enabled {
		return
	}
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	go s.run()
}

func (s *spinner) run() {
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	i := 0
	for {
		select {
		case <-s.stopCh:
			close(s.doneCh)
			return
		case <-ticker.C:
			s.mu.Lock()
			// \r returns to column 0; \033[K clears to end of line so a shorter
			// message never leaves residue from a longer previous one.
			fmt.Fprintf(s.out, "\r%c %s\033[K", spinnerFrames[i%len(spinnerFrames)], s.msg)
			s.mu.Unlock()
			i++
		}
	}
}

// SetMessage updates the text shown next to the spinner.
func (s *spinner) SetMessage(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

func (s *spinner) Stop() {
	if !s.enabled {
		return
	}
	close(s.stopCh)
	<-s.doneCh
	fmt.Fprint(s.out, "\r\033[K") // clear the spinner line
}

// withSpinner runs fn while showing a spinner with the given message. The
// spinner is always stopped, even if fn returns an error.
func withSpinner(msg string, fn func() error) error {
	s := newSpinner(os.Stderr, msg)
	s.Start()
	defer s.Stop()
	return fn()
}
