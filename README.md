# Proyecto Final Sistemas Operativos - Remote Shell & System Resource Monitoring

Credenciales de prueba: usuario `yireth` / clave `linux` (SHA-512 + salt en `ProyOper.users`).
Para crear otro usuario (salt + clave): 
`S=mi_salt; printf '%s' "${S}laClave" | sha512sum | cut -d' ' -f1`  -> línea `usuario:mi_salt:hash`

## Servidor (Debian) - modo desarrollo (sin root)
    cd servidor && go build -o serverOper serverOper.go && ./serverOper
Lee /etc/configProyecto.conf y, si no existe, ../config_etc/configProyecto.conf.

## Cliente (Windows / Linux)
    cd cliente_gui && go mod tidy && go build -o clienteOperativos.exe .
    .\clienteOperativos.exe 192.168.1.10 2810 5     (IP PUERTO PERIODO, opcional)
