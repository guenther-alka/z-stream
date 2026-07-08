// zstream -- encrypted TCP stream transport for ZFS replication
//
// Replaces netcat (nc) in ZFS send/receive pipelines.
// Uses AES-256-GCM authenticated encryption with a session key
// supplied by the caller (job-replicate.pl generates it per transfer).
//
// Usage:
//   Receiver (start first):
//     zstream listen <port> <key> [options]
//     zfs receive -F tank/backup < <(zstream listen <port> <key>)
//
//   Sender:
//     zfs send tank@snap | zstream send <host> <port> <key> [options]
//
//   Tunnel mode (bidirectional encrypted TCP proxy wrapping a child process,
//   used by job-filesync.pl for rclone-over-SFTP transfers):
//     Receiver side (spawns the server, e.g. "rclone serve sftp"):
//       zstream tunnel-listen <port> <key> --local=127.0.0.1:LPORT -- <cmd...>
//     Sender side (spawns the client, e.g. "rclone sync ... :sftp:"):
//       zstream tunnel-send <host> <port> <key> --local=127.0.0.1:LPORT -- <cmd...>
//   In both cases --local=ADDR is the local TCP address the child process
//   binds to (tunnel-listen) or connects to (tunnel-send); zstream proxies
//   all bytes between that local connection and the encrypted tunnel
//   connection to the peer. zstream exits with the child process's exit code.
//
// Options:
//   --buf=128m      Read-ahead buffer size (default 128m). 0 = disabled.
//                   Units: k, m, g (e.g. --buf=256m)
//   --rate=50m      Throughput limit (default: off).
//                   Units: k, m, g per second (e.g. --rate=100m)
//   --progress      Show live progress on stderr (default: off)
//   --log=FILE      Write transfer summary to FILE (default: off)
//                   Example: --log=/tmp/zstream.log
//   --bind=IP       Bind listener to IP (default: 0.0.0.0)
//                   Example: --bind=192.168.1.10
//   --local=ADDR    (tunnel-listen/tunnel-send only) local address the
//                   wrapped child process binds to or connects to.
//
// Key:
//   Any string (hex preferred). job-replicate.pl passes sha256_hex(time+ips+snap).
//   Key is hashed to 32 bytes with SHA-256 internally.
//
// Wire format:
//   [4 bytes BE chunk length][AES-256-GCM nonce 12 bytes][ciphertext][tag 16 bytes]
//   Each chunk is up to 64KB of plaintext, independently encrypted.
//   Chunk length covers nonce+ciphertext+tag (not plaintext length).
//   A zero-length chunk (4 zero bytes) signals end of stream (or, in tunnel
//   mode, end of one direction -- see proxyDuplex).
//
// Build:
//   See zstream.info for per-platform build instructions.
//
// License: BSD 2-Clause -- Copyright (c) 2026 Guenther Alka / napp-it.org

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// version is set via -ldflags "-X main.version=..." at build time
var version = "1.3.0"

const (
	chunkSize      = 65536 // 64 KB plaintext per chunk
	dialTimeout    = 30 * time.Second
	acceptTimeout  = 120 * time.Second
	readTimeout    = 5 * 60 * time.Second // 5 min no-data timeout
	defaultBufSize = 128 * 1024 * 1024    // 128 MB
	localReadyWait = 30 * time.Second     // how long to wait for child to bind --local
	childExitWait  = 10 * time.Second     // how long to wait for child after tunnel closes
)

// options holds parsed CLI flags
type options struct {
	bufSize  int64 // 0 = disabled
	rateHz   int64 // bytes/sec, 0 = unlimited
	progress bool
	logFile  string
	bind     string // listen bind address, default 0.0.0.0
	local    string // tunnel-listen/tunnel-send: local address for child process
}

// parseSize parses "128m", "1g", "512k", or plain bytes
func parseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "0" || s == "off" || s == "no" {
		return 0, nil
	}
	mul := int64(1)
	if strings.HasSuffix(s, "g") {
		mul = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") {
		mul = 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "k") {
		mul = 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size: %q", s)
	}
	return n * mul, nil
}

// parseFlags parses optional flags from args, returns remaining positional args
func parseFlags(args []string) ([]string, options, error) {
	opts := options{
		bufSize: defaultBufSize,
		bind:    "0.0.0.0",
	}
	var pos []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--buf="):
			v, err := parseSize(strings.TrimPrefix(a, "--buf="))
			if err != nil {
				return nil, opts, err
			}
			opts.bufSize = v
		case strings.HasPrefix(a, "--rate="):
			v, err := parseSize(strings.TrimPrefix(a, "--rate="))
			if err != nil {
				return nil, opts, err
			}
			opts.rateHz = v
		case a == "--progress":
			opts.progress = true
		case strings.HasPrefix(a, "--log="):
			opts.logFile = strings.TrimPrefix(a, "--log=")
		case strings.HasPrefix(a, "--bind="):
			opts.bind = strings.TrimPrefix(a, "--bind=")
		case strings.HasPrefix(a, "--local="):
			opts.local = strings.TrimPrefix(a, "--local=")
		default:
			pos = append(pos, a)
		}
	}
	return pos, opts, nil
}

// splitDashDash splits args at the first standalone "--" token.
// Everything before is zstream's own args; everything after is a child
// command + its args, to be exec'd directly (no shell involved).
func splitDashDash(args []string) ([]string, []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// fmtBytes formats bytes as human-readable string
func fmtBytes(n int64) string {
	switch {
	case n >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(1024*1024*1024))
	case n >= 1024*1024:
		return fmt.Sprintf("%.2f MB", float64(n)/float64(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%.2f KB", float64(n)/float64(1024))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// fmtDuration formats duration as mm:ss
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", m, s)
}

// rateLimiter is a simple token bucket: refills every 10ms
type rateLimiter struct {
	rate    int64 // bytes/sec
	tokens  int64 // current available bytes
	lastRef time.Time
}

func newRateLimiter(bytesPerSec int64) *rateLimiter {
	return &rateLimiter{rate: bytesPerSec, tokens: bytesPerSec / 100, lastRef: time.Now()}
}

func (rl *rateLimiter) wait(n int64) {
	for {
		now := time.Now()
		elapsed := now.Sub(rl.lastRef)
		rl.lastRef = now
		add := int64(float64(rl.rate) * elapsed.Seconds())
		rl.tokens += add
		max := rl.rate / 5 // cap tokens at 200ms worth
		if max < int64(chunkSize) {
			max = int64(chunkSize)
		}
		if rl.tokens > max {
			rl.tokens = max
		}
		if rl.tokens >= n {
			rl.tokens -= n
			return
		}
		// Sleep proportional to deficit
		deficit := n - rl.tokens
		sleep := time.Duration(float64(deficit) / float64(rl.rate) * float64(time.Second))
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		time.Sleep(sleep)
	}
}

// progressReporter prints live stats to stderr every second
type progressReporter struct {
	counter *int64
	stop    chan struct{}
	done    chan struct{}
}

func startProgress(counter *int64) *progressReporter {
	pr := &progressReporter{
		counter: counter,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go pr.run()
	return pr
}

func (pr *progressReporter) run() {
	defer close(pr.done)
	start := time.Now()
	var lastBytes int64
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pr.stop:
			fmt.Fprintf(os.Stderr, "\r\033[K") // clear line
			return
		case <-ticker.C:
			cur := atomic.LoadInt64(pr.counter)
			elapsed := time.Since(start)
			speed := float64(cur - lastBytes) // bytes in last second
			lastBytes = cur
			fmt.Fprintf(os.Stderr, "\r  %s | %s/s | %s   ",
				fmtBytes(cur), fmtBytes(int64(speed)), fmtDuration(elapsed))
		}
	}
}

func (pr *progressReporter) Stop() {
	close(pr.stop)
	<-pr.done
}

// writeStats writes the transfer summary to stderr and optionally a log file
func writeStats(logFile string, mode string, total int64, elapsed time.Duration, opts options) {
	speed := int64(0)
	if elapsed.Seconds() > 0 {
		speed = int64(float64(total) / elapsed.Seconds())
	}

	bufInfo := fmtBytes(opts.bufSize)
	if opts.bufSize == 0 {
		bufInfo = "off"
	}
	rateInfo := "off"
	if opts.rateHz > 0 {
		rateInfo = fmtBytes(opts.rateHz) + "/s"
	}

	lines := []string{
		fmt.Sprintf("zstream %s  mode=%-6s  transferred=%s  time=%s  speed=%s/s  buf=%s  rate=%s",
			version, mode,
			fmtBytes(total),
			fmtDuration(elapsed),
			fmtBytes(speed),
			bufInfo,
			rateInfo,
		),
	}

	for _, l := range lines {
		logf("%s", l)
	}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			logf("WARNING: cannot write log %s: %v", logFile, err)
			return
		}
		defer f.Close()
		ts := time.Now().Format("2006.01.02 15:04:05")
		for _, l := range lines {
			fmt.Fprintf(f, "%s  %s\n", ts, l)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := strings.ToLower(os.Args[1])
	switch cmd {
	case "listen":
		pos, opts, err := parseFlags(os.Args[2:])
		if err != nil {
			fatalf("%v", err)
		}
		if len(pos) != 2 {
			fmt.Fprintf(os.Stderr, "usage: zstream listen <port> <key> [options]\n")
			os.Exit(1)
		}
		if len(pos[1]) < 8 {
			fatalf("key too short (min 8 chars) -- empty or weak key rejected")
		}
		doListen(pos[0], pos[1], opts)
	case "send":
		pos, opts, err := parseFlags(os.Args[2:])
		if err != nil {
			fatalf("%v", err)
		}
		if len(pos) != 3 {
			fmt.Fprintf(os.Stderr, "usage: zstream send <host> <port> <key> [options]\n")
			os.Exit(1)
		}
		if len(pos[2]) < 8 {
			fatalf("key too short (min 8 chars) -- empty or weak key rejected")
		}
		doSend(pos[0], pos[1], pos[2], opts)
	case "tunnel-listen":
		ownArgs, childArgs := splitDashDash(os.Args[2:])
		pos, opts, err := parseFlags(ownArgs)
		if err != nil {
			fatalf("%v", err)
		}
		if len(pos) != 2 {
			fmt.Fprintf(os.Stderr, "usage: zstream tunnel-listen <port> <key> --local=ADDR [options] -- <cmd> [args...]\n")
			os.Exit(1)
		}
		if len(pos[1]) < 8 {
			fatalf("key too short (min 8 chars) -- empty or weak key rejected")
		}
		if opts.local == "" {
			fatalf("tunnel-listen requires --local=ADDR (local address the child process binds to)")
		}
		if len(childArgs) == 0 {
			fatalf("tunnel-listen requires a child command after --")
		}
		doTunnelListen(pos[0], pos[1], opts, childArgs)
	case "tunnel-send":
		ownArgs, childArgs := splitDashDash(os.Args[2:])
		pos, opts, err := parseFlags(ownArgs)
		if err != nil {
			fatalf("%v", err)
		}
		if len(pos) != 3 {
			fmt.Fprintf(os.Stderr, "usage: zstream tunnel-send <host> <port> <key> --local=ADDR [options] -- <cmd> [args...]\n")
			os.Exit(1)
		}
		if len(pos[2]) < 8 {
			fatalf("key too short (min 8 chars) -- empty or weak key rejected")
		}
		if opts.local == "" {
			fatalf("tunnel-send requires --local=ADDR (local address the child process connects to)")
		}
		if len(childArgs) == 0 {
			fatalf("tunnel-send requires a child command after --")
		}
		doTunnelSend(pos[0], pos[1], pos[2], opts, childArgs)
	case "version", "--version", "-v":
		fmt.Printf("zstream %s\n", version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "zstream %s -- encrypted TCP stream transport for ZFS replication\n\n", version)
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  zstream listen <port> <key> [options]          listen and decrypt to stdout\n")
	fmt.Fprintf(os.Stderr, "  zstream send   <host> <port> <key> [options]   encrypt stdin and send\n")
	fmt.Fprintf(os.Stderr, "  zstream tunnel-listen <port> <key> --local=ADDR -- <cmd>   spawn cmd, proxy to ADDR\n")
	fmt.Fprintf(os.Stderr, "  zstream tunnel-send <host> <port> <key> --local=ADDR -- <cmd>   spawn cmd, proxy from ADDR\n")
	fmt.Fprintf(os.Stderr, "  zstream version                                print version\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  --buf=SIZE      read-ahead buffer (default 128m, 0=off)  e.g. --buf=256m\n")
	fmt.Fprintf(os.Stderr, "  --rate=SPEED    throughput limit (default off)           e.g. --rate=50m\n")
	fmt.Fprintf(os.Stderr, "  --progress      show live progress on stderr\n")
	fmt.Fprintf(os.Stderr, "  --log=FILE      append transfer summary to FILE\n")
	fmt.Fprintf(os.Stderr, "  --bind=IP       bind listener to IP (default 0.0.0.0)\n")
	fmt.Fprintf(os.Stderr, "  --local=ADDR    tunnel mode: local address for the wrapped child process\n\n")
	fmt.Fprintf(os.Stderr, "Example:\n")
	fmt.Fprintf(os.Stderr, "  # Receiver:\n")
	fmt.Fprintf(os.Stderr, "  zstream listen 9000 MYKEY | zfs receive -F tank/backup\n\n")
	fmt.Fprintf(os.Stderr, "  # Sender (rate-limited, with log):\n")
	fmt.Fprintf(os.Stderr, "  zfs send tank@snap | zstream send 192.168.1.10 9000 MYKEY --rate=100m --log=/tmp/zstream.log\n\n")
	fmt.Fprintf(os.Stderr, "  # Tunnel (rclone-over-sftp folder sync):\n")
	fmt.Fprintf(os.Stderr, "  zstream tunnel-listen 9100 MYKEY --local=127.0.0.1:9101 -- rclone serve sftp /data --addr 127.0.0.1:9101\n")
	fmt.Fprintf(os.Stderr, "  zstream tunnel-send HOST 9100 MYKEY --local=127.0.0.1:9101 -- rclone sync /src :sftp: --sftp-host=127.0.0.1 --sftp-port=9101\n")
}

// deriveKey derives a 32-byte AES key from an arbitrary string via SHA-256.
func deriveKey(keystr string) []byte {
	h := sha256.Sum256([]byte(keystr))
	return h[:]
}

// newGCM creates an AES-256-GCM cipher from a key string.
func newGCM(keystr string) (cipher.AEAD, error) {
	key := deriveKey(keystr)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// doListen opens a TCP listener, accepts one connection, decrypts the stream
// and writes plaintext to stdout.
func doListen(port, keystr string, opts options) {
	listenAddr := opts.bind + ":" + port
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fatalf("listen %s: %v", listenAddr, err)
	}
	defer ln.Close()

	logf("listening on %s  (buf=%s)", listenAddr, func() string {
		if opts.bufSize == 0 {
			return "off"
		}
		return fmtBytes(opts.bufSize)
	}())

	// Accept timeout: don't wait forever for a sender
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(acceptTimeout))
	conn, err := ln.Accept()
	if err != nil {
		fatalf("accept (timeout %s): %v", acceptTimeout, err)
	}
	defer conn.Close()
	ln.Close()

	logf("connection from %s", conn.RemoteAddr())

	// Read timeout: detect dead sender / network failure
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	gcm, err := newGCM(keystr)
	if err != nil {
		fatalf("cipher init: %v", err)
	}

	start := time.Now()
	var counter int64

	var pr *progressReporter
	if opts.progress {
		pr = startProgress(&counter)
	}

	var rl *rateLimiter
	if opts.rateHz > 0 {
		rl = newRateLimiter(opts.rateHz)
	}

	var total int64
	if opts.bufSize > 0 {
		total, err = decryptStreamBuffered(conn, os.Stdout, gcm, opts.bufSize, &counter, rl)
	} else {
		total, err = decryptStream(conn, os.Stdout, gcm, &counter, rl)
	}

	if pr != nil {
		pr.Stop()
	}

	if err != nil {
		fatalf("decrypt: %v", err)
	}

	elapsed := time.Since(start)
	writeStats(opts.logFile, "listen", total, elapsed, opts)
}

// doSend connects to host:port, encrypts stdin and sends the encrypted stream.
func doSend(host, port, keystr string, opts options) {
	addr := net.JoinHostPort(host, port)

	var conn net.Conn
	var err error
	deadline := time.Now().Add(dialTimeout)
	for {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			fatalf("connect %s: %v", addr, err)
		}
		logf("connect %s failed, retrying... (%v)", addr, err)
		time.Sleep(2 * time.Second)
	}
	defer conn.Close()

	logf("connected to %s  (buf=%s)", addr, func() string {
		if opts.bufSize == 0 {
			return "off"
		}
		return fmtBytes(opts.bufSize)
	}())

	gcm, err := newGCM(keystr)
	if err != nil {
		fatalf("cipher init: %v", err)
	}

	start := time.Now()
	var counter int64

	var pr *progressReporter
	if opts.progress {
		pr = startProgress(&counter)
	}

	var rl *rateLimiter
	if opts.rateHz > 0 {
		rl = newRateLimiter(opts.rateHz)
	}

	var total int64
	if opts.bufSize > 0 {
		total, err = encryptStreamBuffered(os.Stdin, conn, gcm, opts.bufSize, &counter, rl)
	} else {
		total, err = encryptStream(os.Stdin, conn, gcm, &counter, rl)
	}

	if pr != nil {
		pr.Stop()
	}

	if err != nil {
		fatalf("encrypt: %v", err)
	}

	elapsed := time.Since(start)
	writeStats(opts.logFile, "send", total, elapsed, opts)
}

// -- Tunnel mode: bidirectional encrypted TCP proxy wrapping a child process --

// waitForLocalReady polls addr until a TCP connection succeeds or timeout.
// Used on the tunnel-listen side to wait for the child process to bind its
// local listener before we accept the encrypted tunnel connection.
func waitForLocalReady(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// exitWithChildResult exits the process with the child's exit code, so a
// caller checking zstream's own exit status sees the wrapped command's result.
func exitWithChildResult(err error) {
	if err == nil {
		os.Exit(0)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		os.Exit(ee.ExitCode())
	}
	logf("child wait error: %v", err)
	os.Exit(1)
}

// proxyDuplex relays bytes bidirectionally between localConn (plaintext,
// the wrapped child process) and tunnelConn (encrypted, the peer zstream),
// using the same chunk framing as listen/send. Half-close is propagated in
// both directions: when one side reaches EOF, the corresponding write side
// of the other connection is closed, so a normal SFTP session (which closes
// cleanly on both ends) shuts down the whole proxy without needing external
// signaling.
func proxyDuplex(localConn, tunnelConn net.Conn) error {
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)

	// tunnel -> local (decrypt)
	go func() {
		defer wg.Done()
		var counter int64
		_, err := decryptStream(tunnelConn, localConn, currentGCM, &counter, nil)
		if err != nil {
			errs[0] = fmt.Errorf("tunnel->local: %w", err)
		}
		if tc, ok := localConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// local -> tunnel (encrypt)
	go func() {
		defer wg.Done()
		var counter int64
		_, err := encryptStream(localConn, tunnelConn, currentGCM, &counter, nil)
		if err != nil {
			errs[1] = fmt.Errorf("local->tunnel: %w", err)
		}
		if tc, ok := tunnelConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	if errs[0] != nil {
		return errs[0]
	}
	return errs[1]
}

// currentGCM is set once per process before proxyDuplex is used. Tunnel mode
// only ever uses a single cipher per process (one tunnel per zstream
// invocation), so a package-level var avoids threading it through both
// proxy goroutines separately.
var currentGCM cipher.AEAD

// doTunnelListen spawns the child command, waits for it to bind opts.local,
// accepts one encrypted tunnel connection on port, and proxies between them.
func doTunnelListen(port, keystr string, opts options, childArgs []string) {
	gcm, err := newGCM(keystr)
	if err != nil {
		fatalf("cipher init: %v", err)
	}
	currentGCM = gcm

	logf("tunnel-listen: starting child: %s", strings.Join(childArgs, " "))
	cmd := exec.Command(childArgs[0], childArgs[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fatalf("cannot start child %q: %v", childArgs[0], err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()

	if !waitForLocalReady(opts.local, localReadyWait) {
		_ = cmd.Process.Kill()
		<-childDone
		fatalf("child did not start listening on %s within %s", opts.local, localReadyWait)
	}
	logf("child is listening on %s", opts.local)

	listenAddr := opts.bind + ":" + port
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_ = cmd.Process.Kill()
		<-childDone
		fatalf("listen %s: %v", listenAddr, err)
	}
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(acceptTimeout))
	tunnelConn, err := ln.Accept()
	ln.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		<-childDone
		fatalf("accept (timeout %s): %v", acceptTimeout, err)
	}
	logf("tunnel connection from %s", tunnelConn.RemoteAddr())
	tunnelConn.SetReadDeadline(time.Now().Add(readTimeout))

	localConn, err := net.DialTimeout("tcp", opts.local, 10*time.Second)
	if err != nil {
		tunnelConn.Close()
		_ = cmd.Process.Kill()
		<-childDone
		fatalf("connect local %s: %v", opts.local, err)
	}

	perr := proxyDuplex(localConn, tunnelConn)
	localConn.Close()
	tunnelConn.Close()

	// The child here is a persistent server (e.g. "rclone serve sftp") --
	// it is expected to keep running until killed, not to exit on its own.
	// A clean proxy session ending means the transfer finished; kill the
	// server now instead of waiting for a voluntary exit that won't happen.
	_ = cmd.Process.Kill()
	<-childDone
	if perr != nil {
		fatalf("proxy error: %v", perr)
	}
	os.Exit(0)
}

// doTunnelSend opens a local listener on opts.local, connects the encrypted
// tunnel to host:port, spawns the child command (which connects into the
// local listener), and proxies between them.
func doTunnelSend(host, port, keystr string, opts options, childArgs []string) {
	gcm, err := newGCM(keystr)
	if err != nil {
		fatalf("cipher init: %v", err)
	}
	currentGCM = gcm

	ln, err := net.Listen("tcp", opts.local)
	if err != nil {
		fatalf("listen local %s: %v", opts.local, err)
	}

	addr := net.JoinHostPort(host, port)
	var tunnelConn net.Conn
	deadline := time.Now().Add(dialTimeout)
	for {
		tunnelConn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			ln.Close()
			fatalf("connect %s: %v", addr, err)
		}
		logf("connect %s failed, retrying... (%v)", addr, err)
		time.Sleep(2 * time.Second)
	}
	logf("connected to %s", addr)
	tunnelConn.SetReadDeadline(time.Now().Add(readTimeout))

	logf("tunnel-send: starting child: %s", strings.Join(childArgs, " "))
	cmd := exec.Command(childArgs[0], childArgs[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		ln.Close()
		tunnelConn.Close()
		fatalf("cannot start child %q: %v", childArgs[0], err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()

	ln.(*net.TCPListener).SetDeadline(time.Now().Add(acceptTimeout))
	localConn, err := ln.Accept()
	ln.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		<-childDone
		tunnelConn.Close()
		fatalf("accept local (timeout %s): %v -- child never connected to --local", acceptTimeout, err)
	}

	if perr := proxyDuplex(localConn, tunnelConn); perr != nil {
		logf("proxy error: %v", perr)
	}
	localConn.Close()
	tunnelConn.Close()

	select {
	case werr := <-childDone:
		exitWithChildResult(werr)
	case <-time.After(childExitWait):
		_ = cmd.Process.Kill()
		<-childDone
		fatalf("child did not exit within %s after tunnel closed", childExitWait)
	}
}

// -- Buffered variants (producer goroutine + channel) --

type chunk struct {
	data []byte
	err  error
}

// encryptStreamBuffered reads stdin in a goroutine into a channel of chunks,
// main goroutine encrypts and sends. Buffer = channel capacity * chunkSize.
func encryptStreamBuffered(r io.Reader, w io.Writer, gcm cipher.AEAD, bufSize int64, counter *int64, rl *rateLimiter) (int64, error) {
	cap_ := int(bufSize / chunkSize)
	if cap_ < 2 {
		cap_ = 2
	}
	ch := make(chan chunk, cap_)

	// Producer: read stdin into channel
	go func() {
		for {
			buf := make([]byte, chunkSize)
			n, readErr := io.ReadFull(r, buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				ch <- chunk{data: b}
			}
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				ch <- chunk{err: io.EOF}
				return
			}
			if readErr != nil {
				ch <- chunk{err: readErr}
				return
			}
		}
	}()

	var total int64
	for c := range ch {
		if c.err == io.EOF {
			break
		}
		if c.err != nil {
			return total, fmt.Errorf("read: %w", c.err)
		}

		if rl != nil {
			rl.wait(int64(len(c.data)))
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return total, fmt.Errorf("nonce: %w", err)
		}
		ciphertext := gcm.Seal(nonce, nonce, c.data, nil)

		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return total, fmt.Errorf("write len: %w", err)
		}
		if _, err := w.Write(ciphertext); err != nil {
			return total, fmt.Errorf("write chunk: %w", err)
		}

		total += int64(len(c.data))
		atomic.StoreInt64(counter, total)
	}

	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return total, fmt.Errorf("write eos: %w", err)
	}
	return total, nil
}

// decryptStreamBuffered decrypts from r, buffers plaintext chunks, writes to w.
func decryptStreamBuffered(r io.Reader, w io.Writer, gcm cipher.AEAD, bufSize int64, counter *int64, rl *rateLimiter) (int64, error) {
	cap_ := int(bufSize / chunkSize)
	if cap_ < 2 {
		cap_ = 2
	}
	ch := make(chan chunk, cap_)
	nonceSize := gcm.NonceSize()

	// Producer: decrypt chunks into channel
	go func() {
		for {
			// Refresh read deadline on each chunk
			if tc, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
				tc.SetReadDeadline(time.Now().Add(readTimeout))
			}
			var lenBuf [4]byte
			if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
				if err == io.EOF {
					ch <- chunk{err: io.EOF}
				} else {
					ch <- chunk{err: fmt.Errorf("read len: %w", err)}
				}
				return
			}
			chunkLen := binary.BigEndian.Uint32(lenBuf[:])
			if chunkLen == 0 {
				ch <- chunk{err: io.EOF}
				return
			}
			maxChunk := uint32(nonceSize + chunkSize + 16)
			if chunkLen > maxChunk {
				ch <- chunk{err: fmt.Errorf("chunk too large: %d -- wrong key?", chunkLen)}
				return
			}
			buf := make([]byte, chunkLen)
			if _, err := io.ReadFull(r, buf); err != nil {
				ch <- chunk{err: fmt.Errorf("read chunk: %w", err)}
				return
			}
			plaintext, err := gcm.Open(nil, buf[:nonceSize], buf[nonceSize:], nil)
			if err != nil {
				ch <- chunk{err: fmt.Errorf("decrypt/auth failed -- wrong key or corrupted data: %w", err)}
				return
			}
			ch <- chunk{data: plaintext}
		}
	}()

	var total int64
	for c := range ch {
		if c.err == io.EOF {
			break
		}
		if c.err != nil {
			return total, c.err
		}
		if rl != nil {
			rl.wait(int64(len(c.data)))
		}
		if _, err := w.Write(c.data); err != nil {
			return total, fmt.Errorf("write plaintext: %w", err)
		}
		total += int64(len(c.data))
		atomic.StoreInt64(counter, total)
	}
	return total, nil
}

// -- Unbuffered variants (original, used when --buf=0, and always in tunnel mode) --

func encryptStream(r io.Reader, w io.Writer, gcm cipher.AEAD, counter *int64, rl *rateLimiter) (int64, error) {
	buf := make([]byte, chunkSize)
	var total int64
	for {
		n, readErr := io.ReadFull(r, buf)
		if n == 0 && readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return total, fmt.Errorf("read: %w", readErr)
		}
		if n == 0 {
			break
		}
		if rl != nil {
			rl.wait(int64(n))
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return total, fmt.Errorf("nonce: %w", err)
		}
		ciphertext := gcm.Seal(nonce, nonce, buf[:n], nil)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return total, fmt.Errorf("write len: %w", err)
		}
		if _, err := w.Write(ciphertext); err != nil {
			return total, fmt.Errorf("write chunk: %w", err)
		}
		total += int64(n)
		atomic.StoreInt64(counter, total)
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return total, fmt.Errorf("write eos: %w", err)
	}
	return total, nil
}

func decryptStream(r io.Reader, w io.Writer, gcm cipher.AEAD, counter *int64, rl *rateLimiter) (int64, error) {
	var total int64
	nonceSize := gcm.NonceSize()
	for {
		// Refresh read deadline on each chunk (5 min between chunks)
		if tc, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
			tc.SetReadDeadline(time.Now().Add(readTimeout))
		}
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			return total, fmt.Errorf("read len: %w", err)
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
		if chunkLen == 0 {
			break
		}
		maxChunk := uint32(nonceSize + chunkSize + 16)
		if chunkLen > maxChunk {
			return total, fmt.Errorf("chunk too large: %d (max %d) -- wrong key?", chunkLen, maxChunk)
		}
		chunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return total, fmt.Errorf("read chunk: %w", err)
		}
		plaintext, err := gcm.Open(nil, chunk[:nonceSize], chunk[nonceSize:], nil)
		if err != nil {
			return total, fmt.Errorf("decrypt/auth failed -- wrong key or corrupted data: %w", err)
		}
		if rl != nil {
			rl.wait(int64(len(plaintext)))
		}
		if _, err := w.Write(plaintext); err != nil {
			return total, fmt.Errorf("write plaintext: %w", err)
		}
		total += int64(len(plaintext))
		atomic.StoreInt64(counter, total)
	}
	return total, nil
}

// logf writes a timestamped message to stderr (not stdout -- stdout is data).
func logf(format string, args ...interface{}) {
	ts := time.Now().Format("2006.01.02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s  zstream  %s\n", ts, fmt.Sprintf(format, args...))
}

func fatalf(format string, args ...interface{}) {
	logf("ERROR "+format, args...)
	os.Exit(1)
}
