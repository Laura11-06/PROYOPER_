// proyOperGUI.go - Cliente gráfico (Fyne v2) del proyecto
// "Remote Shell and System Resource Monitoring". Windows y Linux.
//
// Uso por línea de comandos (opcional, rellena los campos de la interfaz):
//
//	clienteOperativos.exe <IP> <PUERTO> <PERIODO>
//
// Regla de hilos de Fyne v2: todo cambio de widgets hecho desde una goroutine
// distinta a la de la interfaz se envuelve en fyne.Do(func() { ... }).
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const (
	timeoutConexion   = 5 * time.Second
	timeoutLoginRed   = 15 * time.Second
	timeoutEscritura  = 5 * time.Second
	maxCaracteresCons = 200000 // límite del historial visual para mantenerlo fluido
	puertoPorDefecto  = "2810"
	periodoPorDefecto = "5"
)

// ---------------------------------------------------------------------------
// Sesión de red
// ---------------------------------------------------------------------------

type sesionCliente struct {
	conn     net.Conn
	lector   *bufio.Reader
	escritor *bufio.Writer
	mu       sync.Mutex // protege escrituras al socket (GUI + cierre)
	once     sync.Once
	done     chan struct{}
}

func (s *sesionCliente) enviar(linea string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(timeoutEscritura))
	if _, err := s.escritor.WriteString(linea + "\n"); err != nil {
		return err
	}
	return s.escritor.Flush()
}

func (s *sesionCliente) cerrar() {
	s.once.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}

// ---------------------------------------------------------------------------
// Validaciones
// ---------------------------------------------------------------------------

func validarEntradas(ip, puerto, periodo, usuario, clave string) (int, error) {
	ip, puerto, periodo, usuario = strings.TrimSpace(ip), strings.TrimSpace(puerto), strings.TrimSpace(periodo), strings.TrimSpace(usuario)
	if ip == "" || puerto == "" || periodo == "" || usuario == "" || clave == "" {
		return 0, errors.New("todos los campos son obligatorios (IP, puerto, periodo, usuario y contraseña)")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return 0, fmt.Errorf("la IP %q no es una dirección IPv4 válida (ej. 192.168.1.10)", ip)
	}
	p, err := strconv.Atoi(puerto)
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("el puerto debe ser un número entre 1 y 65535")
	}
	per, err := strconv.Atoi(periodo)
	if err != nil || per < 1 || per > 3600 {
		return 0, errors.New("el periodo de reporte debe estar entre 1 y 3600 segundos")
	}
	if strings.ContainsAny(usuario, ":\r\n") || strings.ContainsAny(clave, "\r\n") {
		return 0, errors.New("el usuario no puede contener ':' ni saltos de línea")
	}
	return per, nil
}

// decodificarSalida revierte la codificación del servidor: "\n" -> salto, "\\" -> "\".
func decodificarSalida(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case '\\':
				b.WriteByte('\\')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// main / pantalla de login
// ---------------------------------------------------------------------------

func main() {
	prog := app.New()
	ventana := prog.NewWindow("Proyecto Operativos - Yireth")
	ventana.Resize(fyne.NewSize(860, 600))

	ipEntry := widget.NewEntry()
	ipEntry.SetText("127.0.0.1")
	puertoEntry := widget.NewEntry()
	puertoEntry.SetText(puertoPorDefecto)
	periodoEntry := widget.NewEntry()
	periodoEntry.SetText(periodoPorDefecto)

	estadoLogin := widget.NewLabel("")
	estadoLogin.Wrapping = fyne.TextWrapWord

	// Parámetros por línea de comandos: <IP> <PUERTO> <PERIODO>
	if len(os.Args) == 4 {
		ipEntry.SetText(os.Args[1])
		puertoEntry.SetText(os.Args[2])
		periodoEntry.SetText(os.Args[3])
	} else if len(os.Args) != 1 {
		estadoLogin.SetText("Uso: clienteOperativos <IP> <PUERTO> <PERIODO>  (también puede usar los campos)")
	}

	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("Usuario (ej. yireth)")
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Contraseña")

	var panelLogin fyne.CanvasObject
	var btnConectar *widget.Button
	conectando := false // solo se toca desde el hilo de la interfaz

	var iniciarConexion func()
	iniciarConexion = func() {
		if conectando {
			return
		}
		ip, puerto := strings.TrimSpace(ipEntry.Text), strings.TrimSpace(puertoEntry.Text)
		usuario, clave := strings.TrimSpace(userEntry.Text), passEntry.Text
		periodo, err := validarEntradas(ip, puerto, periodoEntry.Text, usuario, clave)
		if err != nil {
			estadoLogin.SetText("⚠ " + err.Error())
			return
		}

		conectando = true
		btnConectar.Disable()
		estadoLogin.SetText("Conectando con " + net.JoinHostPort(ip, puerto) + " ...")

		go func() {
			ses, prompt, errLogin := conectarYAutenticar(ip, puerto, usuario, clave, periodo)
			fyne.Do(func() {
				conectando = false
				btnConectar.Enable()
				if errLogin != nil {
					estadoLogin.SetText("⚠ " + errLogin.Error())
					return
				}
				passEntry.SetText("")
				estadoLogin.SetText("")
				abrirConsola(ventana, ses, prompt, panelLogin, estadoLogin)
			})
		}()
	}

	btnConectar = widget.NewButton("Conectar e Iniciar Sesión", iniciarConexion)
	passEntry.OnSubmitted = func(string) { iniciarConexion() }

	panelLogin = container.NewCenter(container.NewVBox(
		widget.NewLabelWithStyle("SISTEMAS OPERATIVOS - SHELL REMOTA & MONITOR", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("IP Servidor:", ipEntry),
			widget.NewFormItem("Puerto:", puertoEntry),
			widget.NewFormItem("Periodo (s):", periodoEntry),
			widget.NewFormItem("Usuario:", userEntry),
			widget.NewFormItem("Password:", passEntry),
		),
		btnConectar,
		estadoLogin,
	))

	ventana.SetContent(panelLogin)
	ventana.ShowAndRun()
}

// conectarYAutenticar corre en una goroutine (nunca bloquea la interfaz).
// Abre un socket nuevo por intento: el servidor lleva la cuenta de fallos por IP.
func conectarYAutenticar(ip, puerto, usuario, clave string, periodo int) (*sesionCliente, string, error) {
	direccion := net.JoinHostPort(ip, puerto)
	conn, err := net.DialTimeout("tcp4", direccion, timeoutConexion)
	if err != nil {
		return nil, "", fmt.Errorf("no se pudo conectar con %s: %v", direccion, err)
	}
	ses := &sesionCliente{
		conn:     conn,
		lector:   bufio.NewReader(conn),
		escritor: bufio.NewWriter(conn),
		done:     make(chan struct{}),
	}

	conn.SetDeadline(time.Now().Add(timeoutLoginRed))
	if err := ses.enviar(fmt.Sprintf("LOGIN %s:%s:%d", usuario, clave, periodo)); err != nil {
		ses.cerrar()
		return nil, "", fmt.Errorf("error enviando credenciales: %v", err)
	}
	resp, err := ses.lector.ReadString('\n')
	if err != nil {
		ses.cerrar()
		var ne net.Error
		switch {
		case errors.Is(err, io.EOF):
			return nil, "", errors.New("el servidor cerró la conexión sin responder")
		case errors.As(err, &ne) && ne.Timeout():
			return nil, "", errors.New("el servidor no respondió a tiempo")
		default:
			return nil, "", fmt.Errorf("error de red durante el login: %v", err)
		}
	}
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "AUTH_OK|") {
		ses.cerrar()
		if resp == "" {
			resp = "respuesta vacía del servidor"
		}
		return nil, "", errors.New(resp)
	}
	conn.SetDeadline(time.Time{})
	return ses, strings.TrimPrefix(resp, "AUTH_OK|"), nil
}

// ---------------------------------------------------------------------------
// Consola remota
// ---------------------------------------------------------------------------

func abrirConsola(ventana fyne.Window, ses *sesionCliente, promptInicial string, panelLogin fyne.CanvasObject, estadoLogin *widget.Label) {
	labelReporte := widget.NewLabelWithStyle("Esperando reporte del servidor...", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	labelReporte.Wrapping = fyne.TextWrapWord
	labelPrompt := widget.NewLabelWithStyle(promptInicial, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Consola de salida: Label monoespaciado dentro de un VScroll.
	labelRes := widget.NewLabel("Autenticación exitosa. Listo para ejecutar comandos (soporta tuberías | y cd).\n")
	labelRes.TextStyle = fyne.TextStyle{Monospace: true}
	labelRes.Wrapping = fyne.TextWrapBreak
	scroll := container.NewVScroll(labelRes)

	// Solo se llama desde el hilo de la interfaz (callbacks o dentro de fyne.Do).
	bajarScroll := func() {
		scroll.Refresh()
		scroll.ScrollToBottom()
		// Segundo intento tras el re-layout, para salidas largas (ps aux, ls -la).
		time.AfterFunc(60*time.Millisecond, func() {
			fyne.Do(func() { scroll.ScrollToBottom() })
		})
	}
	agregarTexto := func(t string) {
		texto := labelRes.Text + t
		if len(texto) > maxCaracteresCons {
			texto = texto[len(texto)-maxCaracteresCons:]
			if i := strings.IndexByte(texto, '\n'); i >= 0 {
				texto = texto[i+1:]
			}
		}
		labelRes.SetText(texto)
		bajarScroll()
	}

	textComando := widget.NewEntry()
	textComando.SetPlaceHolder("Escriba el comando (ej. ls -la | grep go, ps aux, cd /tmp, bye)")

	btnEjecutar := widget.NewButton("Ejecutar", nil)
	btnLimpiar := widget.NewButton("Limpiar", func() {
		labelRes.SetText("")
		scroll.ScrollToTop()
	})
	btnSalir := widget.NewButton("Salir (bye)", nil)
	btnVolver := widget.NewButton("Nueva conexión", nil)
	btnVolver.Hide()

	// Deshabilita los controles al terminar la sesión (se llama dentro de fyne.Do).
	desactivarControles := func() {
		textComando.Disable()
		btnEjecutar.Disable()
		btnSalir.Disable()
		btnVolver.Show()
	}

	enviarComando := func() {
		cmd := strings.TrimSpace(textComando.Text)
		if cmd == "" {
			return
		}
		agregarTexto("\n" + labelPrompt.Text + " " + cmd + "\n")
		textComando.SetText("")
		go func() {
			if err := ses.enviar(cmd); err != nil {
				fyne.Do(func() {
					desactivarControles()
					labelReporte.SetText("CONEXIÓN PERDIDA CON EL SERVIDOR")
					dialog.ShowError(fmt.Errorf("no se pudo enviar el comando: %v", err), ventana)
				})
				ses.cerrar()
			}
		}()
	}
	btnEjecutar.OnTapped = enviarComando
	textComando.OnSubmitted = func(string) { enviarComando() }

	btnSalir.OnTapped = func() {
		btnSalir.Disable()
		go func() {
			if err := ses.enviar("bye"); err != nil {
				ses.cerrar() // si no se puede enviar, se cierra el socket localmente
			}
		}()
	}

	btnVolver.OnTapped = func() {
		estadoLogin.SetText("")
		ventana.SetContent(panelLogin)
	}

	// Cerrar la ventana envía "bye" de forma limpia y luego sale.
	ventana.SetCloseIntercept(func() {
		select {
		case <-ses.done:
		default:
			ses.enviar("bye")
			ses.cerrar()
		}
		ventana.Close()
	})

	// Goroutine de lectura: reportes de telemetría y respuestas de comandos.
	go func() {
		defer ses.cerrar()
		for {
			linea, err := ses.lector.ReadString('\n')
			if err != nil {
				select {
				case <-ses.done: // cierre local o por bye: ya se gestionó
					return
				default:
				}
				mensaje := "Se perdió la conexión con el servidor."
				if errors.Is(err, io.EOF) {
					mensaje = "El servidor cerró la conexión."
				}
				fyne.Do(func() {
					desactivarControles()
					labelReporte.SetText("CONEXIÓN PERDIDA CON EL SERVIDOR")
					agregarTexto("\n[" + mensaje + "]\n")
					dialog.ShowInformation("Conexión finalizada", mensaje, ventana)
				})
				return
			}
			l := strings.TrimSpace(linea)

			switch {
			case strings.HasPrefix(l, "Reporte"):
				fyne.Do(func() { labelReporte.SetText(l) })

			case l == "SALIENDO":
				fyne.Do(func() {
					desactivarControles()
					labelReporte.SetText("Sesión finalizada (bye)")
					agregarTexto("\n[Sesión cerrada correctamente]\n")
				})
				return

			case strings.HasPrefix(l, "RESP|"):
				partes := strings.SplitN(l, "|", 3)
				if len(partes) == 3 {
					prompt, salida := partes[1], decodificarSalida(partes[2])
					fyne.Do(func() {
						labelPrompt.SetText(prompt)
						agregarTexto(salida + "\n")
					})
				}
			}
		}
	}()

	barra := container.NewHBox(btnLimpiar, btnSalir, btnVolver)
	zonaInferior := container.NewVBox(
		labelPrompt,
		container.NewBorder(nil, nil, nil, btnEjecutar, textComando),
		barra,
	)
	ventana.SetContent(container.NewBorder(
		container.NewVBox(labelReporte, widget.NewSeparator()),
		zonaInferior, nil, nil,
		scroll,
	))
	ventana.Canvas().Focus(textComando)
}
