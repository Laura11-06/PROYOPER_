// serverOper.go - Servidor concurrente "Remote Shell and System Resource Monitoring".
// Sistemas Operativos - Universidad de los Llanos (IDEAD).
//
// Un único socket TCP/IPv4 multiplexa tres flujos delimitados por '\n':
//  1. Autenticación (SHA-512 + salt) con control de IP y bloqueo por intentos.
//  2. Ejecución remota de comandos (goroutine de recepción).
//  3. Telemetría periódica (goroutine de envío).
//
// Compilar: go build -o serverOper serverOper.go
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// Rutas de configuración: primero /etc y, si no existen, respaldo relativo.
	rutaConfEtc       = "/etc/configProyecto.conf"
	rutaConfRespaldo  = "../config_etc/configProyecto.conf"
	rutaUsersEtc      = "/etc/ProyOper.users"
	rutaUsersRespaldo = "../config_etc/ProyOper.users"

	puertoPorDefecto  = 2810
	periodoPorDefecto = 5
	periodoMin        = 1
	periodoMax        = 3600

	timeoutLogin     = 60 * time.Second // tiempo máximo para completar el login
	timeoutEscritura = 10 * time.Second // evita bloqueos al escribir a un cliente muerto
	timeoutComando   = 60 * time.Second // tiempo máximo por comando remoto
	duracionBloqueo  = 5 * time.Minute  // bloqueo de una IP tras max_attempts fallos
	maxLinea         = 64 * 1024        // longitud máxima de una trama recibida
	maxSalida        = 256 * 1024       // salida máxima de un comando enviada al cliente
)

// Comandos interactivos que necesitan TTY y bloquearían la sesión.
var comandosInteractivos = map[string]bool{
	"nano": true, "vim": true, "vi": true, "top": true,
	"htop": true, "less": true, "more": true,
}

var errLineaLarga = errors.New("trama demasiado larga")

// auditor registra todo en el .log (o en stdout si el archivo no es utilizable).
var auditor = log.New(os.Stdout, "", log.LstdFlags)

// dirInicial es el directorio de trabajo con el que arrancó el servidor.
var dirInicial = "/"

func logf(formato string, args ...interface{}) {
	auditor.Printf(formato, args...)
}

// ---------------------------------------------------------------------------
// Configuración
// ---------------------------------------------------------------------------

type ConfigServer struct {
	Puerto      int
	AllowIPs    []string
	AllowUsers  []string
	MaxAttempts int
	UsersDB     string
	LogFile     string
	Blacklist   map[string]bool
}

func configPorDefecto() ConfigServer {
	bl := map[string]bool{
		"rm": true, "mkfs": true, "dd": true, "shutdown": true,
		"reboot": true, "init": true, "halt": true, "poweroff": true,
		"passwd": true, "su": true, "sudo": true, "kill": true, "killall": true,
	}
	for k, v := range comandosInteractivos {
		bl[k] = v
	}
	return ConfigServer{
		Puerto:      puertoPorDefecto,
		AllowIPs:    []string{"*"},
		AllowUsers:  []string{"yireth", "luis", "maria", "juan"},
		MaxAttempts: 3,
		UsersDB:     rutaUsersRespaldo,
		LogFile:     "../config_etc/proyOper.log",
		Blacklist:   bl,
	}
}

func listaCSV(s string) []string {
	var res []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, p)
		}
	}
	return res
}

// cargarConfiguracion lee /etc/configProyecto.conf y, si no existe,
// ../config_etc/configProyecto.conf. Devuelve la configuración y su origen.
func cargarConfiguracion() (ConfigServer, string) {
	cfg := configPorDefecto()
	var datos []byte
	origen := "valores por defecto (no se encontró archivo de configuración)"
	for _, ruta := range []string{rutaConfEtc, rutaConfRespaldo} {
		d, err := os.ReadFile(ruta)
		if err == nil {
			datos, origen = d, ruta
			break
		}
	}
	for _, linea := range strings.Split(string(datos), "\n") {
		linea = strings.TrimSpace(linea)
		if linea == "" || strings.HasPrefix(linea, "#") {
			continue
		}
		kv := strings.SplitN(linea, "=", 2)
		if len(kv) != 2 {
			continue
		}
		clave, valor := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch clave {
		case "puerto":
			if n, err := strconv.Atoi(valor); err == nil && n >= 1 && n <= 65535 {
				cfg.Puerto = n
			}
		case "allowips":
			if l := listaCSV(valor); len(l) > 0 {
				cfg.AllowIPs = l
			}
		case "allowusers":
			cfg.AllowUsers = listaCSV(valor)
		case "max_attempts":
			if n, err := strconv.Atoi(valor); err == nil && n >= 1 {
				cfg.MaxAttempts = n
			}
		case "users_db":
			if valor != "" {
				cfg.UsersDB = valor
			}
		case "log_file":
			if valor != "" {
				cfg.LogFile = valor
			}
		case "blacklist":
			nuevaBL := make(map[string]bool)
			for k, v := range comandosInteractivos {
				nuevaBL[k] = v
			}
			for _, item := range listaCSV(valor) {
				nuevaBL[filepath.Base(item)] = true
			}
			cfg.Blacklist = nuevaBL
		}
	}
	// Rutas absolutas: así no dependen del directorio de trabajo.
	if abs, err := filepath.Abs(cfg.UsersDB); err == nil {
		cfg.UsersDB = abs
	}
	if abs, err := filepath.Abs(cfg.LogFile); err == nil {
		cfg.LogFile = abs
	}
	return cfg, origen
}

// rutaUsersEfectiva devuelve la primera base de usuarios que exista.
func rutaUsersEfectiva(cfg ConfigServer) string {
	for _, r := range []string{cfg.UsersDB, rutaUsersEtc, rutaUsersRespaldo} {
		if _, err := os.Stat(r); err == nil {
			return r
		}
	}
	return cfg.UsersDB
}

// iniciarLog abre el .log en modo append. Si no se puede (permisos, ruta
// inexistente) hace fallback a os.Stdout. Devuelve la función de cierre.
func iniciarLog(ruta string) func() {
	f, err := os.OpenFile(ruta, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AVISO: no se puede escribir el log %q (%v); se usará la salida estándar\n", ruta, err)
		auditor = log.New(os.Stdout, "", log.LstdFlags)
		return func() {}
	}
	auditor = log.New(io.MultiWriter(f, os.Stdout), "", log.LstdFlags)
	return func() { f.Close() }
}

// ---------------------------------------------------------------------------
// Registro de fallos y bloqueos por IP (compartido entre conexiones)
// ---------------------------------------------------------------------------

type registroIP struct {
	mu       sync.Mutex
	fallos   map[string]int
	bloqueos map[string]time.Time
}

func nuevoRegistroIP() *registroIP {
	return &registroIP{fallos: map[string]int{}, bloqueos: map[string]time.Time{}}
}

func (r *registroIP) bloqueada(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	hasta, ok := r.bloqueos[ip]
	if !ok {
		return false
	}
	if time.Now().After(hasta) {
		delete(r.bloqueos, ip)
		delete(r.fallos, ip)
		return false
	}
	return true
}

// fallo registra un intento fallido; devuelve el nº de fallos y si la IP quedó bloqueada.
func (r *registroIP) fallo(ip string, max int) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallos[ip]++
	n := r.fallos[ip]
	if n >= max {
		r.bloqueos[ip] = time.Now().Add(duracionBloqueo)
		return n, true
	}
	return n, false
}

func (r *registroIP) exito(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.fallos, ip)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	fmt.Println("***************************")
	fmt.Println("**   SERVER OPER YIRETH  **")
	fmt.Println("***************************")

	if d, err := os.Getwd(); err == nil {
		dirInicial = d
	}

	cfg, origen := cargarConfiguracion()
	cerrarLog := iniciarLog(cfg.LogFile)
	defer cerrarLog()

	logf("SERVIDOR_INICIO config=%s users_db=%s log=%s", origen, rutaUsersEfectiva(cfg), cfg.LogFile)

	oyente, err := net.Listen("tcp4", ":"+strconv.Itoa(cfg.Puerto))
	if err != nil {
		logf("ERROR iniciando servidor en puerto %d: %v", cfg.Puerto, err)
		return
	}
	defer oyente.Close()
	logf("Servidor escuchando en puerto %d (max_attempts=%d)", cfg.Puerto, cfg.MaxAttempts)

	// Cierre ordenado con SIGINT/SIGTERM (systemctl stop).
	senales := make(chan os.Signal, 1)
	signal.Notify(senales, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-senales
		logf("SERVIDOR_FIN señal=%v", s)
		oyente.Close()
	}()

	registro := nuevoRegistroIP()
	for {
		conn, err := oyente.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		ip := ipDe(conn.RemoteAddr())
		if !ipPermitida(ip, cfg.AllowIPs) {
			logf("IP_NO_AUTORIZADA ip=%s", ip)
			rechazar(conn, "ERROR_IP: Dirección IP no autorizada")
			continue
		}
		if registro.bloqueada(ip) {
			logf("IP_BLOQUEADA_RECHAZADA ip=%s", ip)
			rechazar(conn, "AUTH_BLOCKED: IP bloqueada temporalmente")
			continue
		}
		go manejarCliente(conn, cfg, registro)
	}
}

func rechazar(conn net.Conn, mensaje string) {
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte(mensaje + "\n"))
	conn.Close()
}

func ipDe(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// ---------------------------------------------------------------------------
// Sesión de cliente
// ---------------------------------------------------------------------------

type sesion struct {
	conn     net.Conn
	lector   *bufio.Reader
	escritor *bufio.Writer
	mu       sync.Mutex // protege escritor/socket (escriben 2 goroutines)
	done     chan struct{}
	once     sync.Once // protege el cierre de done
	usuario  string
	ip       string
	ipLocal  string
	cwd      string // directorio de trabajo de ESTA sesión (solo lo usa recMensajeS)
	cfg      ConfigServer
}

func (s *sesion) cerrar() { s.once.Do(func() { close(s.done) }) }

func (s *sesion) enviar(linea string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(timeoutEscritura))
	if _, err := s.escritor.WriteString(linea); err != nil {
		return err
	}
	return s.escritor.Flush()
}

func (s *sesion) prompt() string {
	return fmt.Sprintf("%s@%s%s:%%", s.usuario, s.ipLocal, s.cwd)
}

// recuperar evita que un pánico en una goroutine tumbe todo el servidor.
func (s *sesion) recuperar(nombre string) {
	if r := recover(); r != nil {
		logf("PANIC %s usuario=%q ip=%s: %v\n%s", nombre, s.usuario, s.ip, r, debug.Stack())
		s.cerrar()
	}
}

// manejarCliente atiende una conexión completa. Un fallo aquí nunca afecta al servidor.
func manejarCliente(conn net.Conn, cfg ConfigServer, registro *registroIP) {
	defer conn.Close()
	ip := ipDe(conn.RemoteAddr())
	defer func() {
		if r := recover(); r != nil {
			logf("PANIC manejarCliente ip=%s: %v\n%s", ip, r, debug.Stack())
		}
	}()

	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	lector := bufio.NewReaderSize(conn, maxLinea)
	ipLocal := ipDe(conn.LocalAddr())

	// Fase de login con plazo máximo: evita sockets zombis.
	conn.SetDeadline(time.Now().Add(timeoutLogin))
	usuario, periodo, ok := autenticar(conn, lector, cfg, registro, ip)
	if !ok {
		return
	}
	conn.SetDeadline(time.Time{}) // se quita el plazo al entrar en sesión

	s := &sesion{
		conn:     conn,
		lector:   lector,
		escritor: bufio.NewWriter(conn),
		done:     make(chan struct{}),
		usuario:  usuario,
		ip:       ip,
		ipLocal:  ipLocal,
		cwd:      dirInicial,
		cfg:      cfg,
	}
	if err := s.enviar("AUTH_OK|" + s.prompt() + "\n"); err != nil {
		logf("ERROR enviando AUTH_OK usuario=%q ip=%s: %v", usuario, ip, err)
		return
	}
	logf("LOGIN_OK usuario=%q ip=%s periodo=%ds", usuario, ip, periodo)

	go s.envMensajeS(periodo)
	go s.recMensajeS()
	<-s.done
	logf("SESION_CERRADA usuario=%q ip=%s", usuario, ip)
}

// autenticar ejecuta el protocolo LOGIN <usuario>:<contraseña>:<periodo>.
func autenticar(conn net.Conn, lector *bufio.Reader, cfg ConfigServer, registro *registroIP, ip string) (string, int, bool) {
	escribir := func(msg string) {
		conn.SetWriteDeadline(time.Now().Add(timeoutEscritura))
		conn.Write([]byte(msg + "\n"))
	}

	for {
		linea, err := leerLinea(lector)
		if err != nil {
			if isTimeout(err) {
				logf("LOGIN_TIMEOUT ip=%s", ip)
			}
			return "", 0, false
		}

		usuario, pass, periodo, formatoOK := parsearLogin(linea)
		valido := false
		permitido := false
		if formatoOK {
			valido = validarCredenciales(rutaUsersEfectiva(cfg), usuario, pass)
			permitido = usuarioPermitido(usuario, cfg.AllowUsers)
		}
		// Limpia la contraseña de la RAM (buffer de la trama y copia).
		for i := range pass {
			pass[i] = 0
		}
		for i := range linea {
			linea[i] = 0
		}

		if formatoOK && valido && permitido {
			registro.exito(ip)
			return usuario, periodo, true
		}

		if !formatoOK {
			logf("LOGIN_FORMATO_INVALIDO ip=%s", ip)
		} else if valido && !permitido {
			logf("LOGIN_USUARIO_NO_PERMITIDO usuario=%q ip=%s", usuario, ip)
		} else {
			logf("LOGIN_FALLIDO usuario=%q ip=%s", usuario, ip)
		}

		n, bloqueada := registro.fallo(ip, cfg.MaxAttempts)
		if bloqueada {
			logf("IP_BLOQUEADA ip=%s tras %d intentos fallidos (%v)", ip, n, duracionBloqueo)
			escribir("AUTH_BLOCKED: Máximo de intentos alcanzado")
			return "", 0, false
		}
		escribir(fmt.Sprintf("AUTH_FAIL: Credenciales incorrectas (%d/%d)", n, cfg.MaxAttempts))
		time.Sleep(time.Duration(n) * 500 * time.Millisecond) // espera progresiva
	}
}

// parsearLogin interpreta "LOGIN usuario:contraseña:periodo". La contraseña
// puede contener ':'; el periodo es el último campo si es numérico.
func parsearLogin(linea []byte) (usuario string, pass []byte, periodo int, ok bool) {
	if !bytes.HasPrefix(linea, []byte("LOGIN ")) {
		return "", nil, 0, false
	}
	cuerpo := linea[len("LOGIN "):]
	i := bytes.IndexByte(cuerpo, ':')
	if i < 0 {
		return "", nil, 0, false
	}
	usuario = strings.TrimSpace(string(cuerpo[:i]))
	resto := cuerpo[i+1:]
	periodo = periodoPorDefecto
	if j := bytes.LastIndexByte(resto, ':'); j >= 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(string(resto[j+1:]))); err == nil {
			periodo = n
			resto = resto[:j]
		}
	}
	if periodo < periodoMin {
		periodo = periodoMin
	}
	if periodo > periodoMax {
		periodo = periodoMax
	}
	pass = append([]byte(nil), resto...)
	return usuario, pass, periodo, usuario != ""
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// leerLinea lee una trama terminada en '\n' y devuelve una copia sin el salto.
func leerLinea(r *bufio.Reader) ([]byte, error) {
	l, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err // incluye bufio.ErrBufferFull (trama demasiado larga)
	}
	return append([]byte(nil), bytes.TrimRight(l, "\r\n")...), nil
}

// ---------------------------------------------------------------------------
// Telemetría (goroutine de envío)
// ---------------------------------------------------------------------------

func (s *sesion) envMensajeS(periodo int) {
	defer s.recuperar("envMensajeS")
	defer s.cerrar()

	medidor := nuevoMedidorCPU()
	ticker := time.NewTicker(time.Duration(periodo) * time.Second)
	defer ticker.Stop()

	// Pequeña espera inicial para que el primer cálculo de CPU tenga datos.
	select {
	case <-s.done:
		return
	case <-time.After(300 * time.Millisecond):
	}

	num := 0
	for {
		num++
		reporte := fmt.Sprintf("Reporte (%d) [cada %ds]: %s\n", num, periodo, obtenerMetricas(medidor))
		if err := s.enviar(reporte); err != nil {
			return
		}
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
	}
}

type medidorCPU struct{ idle, total uint64 }

func leerCPU() (idle, total uint64, ok bool) {
	d, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	linea := strings.SplitN(string(d), "\n", 2)[0]
	campos := strings.Fields(linea)
	if len(campos) < 5 || campos[0] != "cpu" {
		return 0, 0, false
	}
	for i, c := range campos[1:] {
		if i >= 8 { // user nice system idle iowait irq softirq steal
			break
		}
		v, err := strconv.ParseUint(c, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += v
		if i == 3 || i == 4 {
			idle += v
		}
	}
	return idle, total, true
}

func nuevoMedidorCPU() *medidorCPU {
	m := &medidorCPU{}
	m.idle, m.total, _ = leerCPU()
	return m
}

func (m *medidorCPU) uso() string {
	idle, total, ok := leerCPU()
	if !ok {
		return "N/A"
	}
	dI, dT := idle-m.idle, total-m.total
	m.idle, m.total = idle, total
	if dT == 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", (1-float64(dI)/float64(dT))*100)
}

func ejecutarSimple(nombre string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, nombre, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	return string(out), err
}

func obtenerMetricas(m *medidorCPU) string {
	return fmt.Sprintf("[CPU=%s | RAM=%s | DD=%s | nProc=%s]", m.uso(), obtenerRAM(), obtenerDisco(), obtenerProcesos())
}

func obtenerRAM() string {
	out, err := ejecutarSimple("free", "-m")
	if err != nil {
		return "N/A"
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == "Mem:" {
			total, e1 := strconv.Atoi(f[1])
			usado, e2 := strconv.Atoi(f[2])
			if e1 != nil || e2 != nil || total == 0 {
				return "N/A"
			}
			return fmt.Sprintf("%dMB/%dMB (%.1f%%)", usado, total, float64(usado)*100/float64(total))
		}
	}
	return "N/A"
}

func obtenerDisco() string {
	out, err := ejecutarSimple("df", "-h", "/")
	if err != nil {
		return "N/A"
	}
	lineas := strings.Split(strings.TrimSpace(out), "\n")
	if len(lineas) < 2 {
		return "N/A"
	}
	f := strings.Fields(lineas[1])
	if len(f) < 5 {
		return "N/A"
	}
	return f[4]
}

func obtenerProcesos() string {
	out, err := ejecutarSimple("ps", "-e", "--no-headers")
	if err != nil {
		return "N/A"
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return strconv.Itoa(n)
}

// ---------------------------------------------------------------------------
// Ejecución remota (goroutine de recepción)
// ---------------------------------------------------------------------------

func (s *sesion) recMensajeS() {
	defer s.recuperar("recMensajeS")
	defer s.cerrar()

	for {
		l, err := leerLinea(s.lector)
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				logf("TRAMA_DEMASIADO_LARGA usuario=%q ip=%s", s.usuario, s.ip)
			}
			return // EOF, socket cerrado o error de red: termina la sesión
		}
		comando := strings.TrimSpace(string(l))
		if comando == "" {
			continue
		}

		if strings.EqualFold(comando, "bye") {
			logf("BYE usuario=%q ip=%s", s.usuario, s.ip)
			s.enviar("SALIENDO\n")
			return
		}

		logf("CMD usuario=%q ip=%s cmd=%q", s.usuario, s.ip, comando)
		salida := s.ejecutarComando(comando)
		if err := s.enviar("RESP|" + s.prompt() + "|" + codificarSalida(salida) + "\n"); err != nil {
			return
		}
	}
}

var reemplazoSalida = strings.NewReplacer("\\", "\\\\", "\r", "", "\n", "\\n")

// codificarSalida convierte la salida en UNA línea: "\n" -> "\\n", "\" -> "\\".
func codificarSalida(s string) string {
	s = strings.TrimRight(s, "\r\n")
	if strings.TrimSpace(s) == "" {
		return "OK"
	}
	return reemplazoSalida.Replace(s)
}

func (s *sesion) ejecutarComando(comando string) string {
	// Comandos interactivos sin TTY.
	segmentos := strings.FieldsFunc(comando, func(r rune) bool { return r == '|' || r == ';' || r == '&' })
	for _, seg := range segmentos {
		campos := strings.Fields(seg)
		if len(campos) == 0 {
			continue
		}
		base := filepath.Base(campos[0])
		if s.cfg.Blacklist[base] {
			logf("CMD_BLOQUEADO usuario=%q ip=%s cmd=%q", s.usuario, s.ip, base)
			if comandosInteractivos[base] {
				return fmt.Sprintf("[BLOQUEADO] '%s' es interactivo y requiere TTY; no está soportado en esta shell remota.", base)
			}
			return fmt.Sprintf("[BLOQUEADO] El comando '%s' está prohibido por la lista negra del servidor.", base)
		}
	}

	// cd simple: cambia el directorio persistente de la sesión.
	if (comando == "cd" || strings.HasPrefix(comando, "cd ")) && !strings.ContainsAny(comando, "|;&<>`$") {
		return s.cambiarDirectorio(strings.TrimSpace(strings.TrimPrefix(comando, "cd")))
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutComando)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", comando)
	cmd.Dir = s.cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second

	salida, err := cmd.CombinedOutput()
	texto := string(salida)
	if len(texto) > maxSalida {
		texto = texto[:maxSalida] + "\n[... salida truncada ...]"
	}
	if ctx.Err() == context.DeadlineExceeded {
		return texto + fmt.Sprintf("\n[TIMEOUT] El comando superó %v y fue terminado.", timeoutComando)
	}
	if err != nil && len(salida) == 0 {
		return fmt.Sprintf("[ERROR]: %s", err)
	}
	return texto
}

func (s *sesion) cambiarDirectorio(arg string) string {
	arg = strings.Trim(arg, `"'`)
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/"
	}
	var destino string
	switch {
	case arg == "" || arg == "~":
		destino = home
	case strings.HasPrefix(arg, "~/"):
		destino = filepath.Join(home, arg[2:])
	case filepath.IsAbs(arg):
		destino = arg
	default:
		destino = filepath.Join(s.cwd, arg)
	}
	destino = filepath.Clean(destino)

	info, err := os.Stat(destino)
	if err != nil {
		return fmt.Sprintf("cd: no se puede acceder a '%s': %v", arg, err)
	}
	if !info.IsDir() {
		return fmt.Sprintf("cd: '%s' no es un directorio", arg)
	}
	f, err := os.Open(destino)
	if err != nil {
		return fmt.Sprintf("cd: permiso denegado: '%s'", arg)
	}
	f.Close()
	s.cwd = destino
	return ""
}

// ---------------------------------------------------------------------------
// Utilidades de autenticación
// ---------------------------------------------------------------------------

func ipPermitida(ip string, lista []string) bool {
	for _, item := range lista {
		item = strings.TrimSpace(item)
		if item == "*" || item == ip {
			return true
		}
	}
	return false
}

func usuarioPermitido(usuario string, lista []string) bool {
	for _, item := range lista {
		if strings.TrimSpace(item) == usuario {
			return true
		}
	}
	return false
}

// hashSHA512 calcula SHA-512(salt || contraseña) en hexadecimal.
func hashSHA512(salt string, pass []byte) string {
	h := sha512.New()
	h.Write([]byte(salt))
	h.Write(pass)
	return hex.EncodeToString(h.Sum(nil))
}

// buscarUsuario localiza "usuario:salt:hash" en la base plana.
func buscarUsuario(rutaDB, usuario string) (salt, hash string, ok bool) {
	datos, err := os.ReadFile(rutaDB)
	if err != nil {
		return "", "", false
	}
	for _, registro := range strings.Split(string(datos), "\n") {
		registro = strings.TrimSpace(registro)
		if registro == "" || strings.HasPrefix(registro, "#") {
			continue
		}
		p := strings.SplitN(registro, ":", 3)
		if len(p) == 3 && strings.TrimSpace(p[0]) == usuario {
			return strings.TrimSpace(p[1]), strings.ToLower(strings.TrimSpace(p[2])), true
		}
	}
	return "", "", false
}

// validarCredenciales compara en tiempo constante (y calcula el hash aunque el
// usuario no exista, para no revelar por tiempo qué usuarios existen).
func validarCredenciales(rutaDB, usuario string, pass []byte) bool {
	salt, esperado, existe := buscarUsuario(rutaDB, usuario)
	if !existe {
		salt, esperado = "sin-salt", strings.Repeat("0", 128)
	}
	calculado := hashSHA512(salt, pass)
	iguales := subtle.ConstantTimeCompare([]byte(calculado), []byte(esperado)) == 1
	return existe && iguales
}