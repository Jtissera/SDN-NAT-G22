# Enrutador NAT/PAT con SDN (Controlador POX)

Este proyecto implementa un enrutador basado en Redes Definidas por Software (SDN) con capacidades de Traducción de Direcciones de Red y Puertos (NAT/PAT). Utiliza el controlador **POX** y **Mininet** para simular un entorno donde múltiples hosts de una red privada (LAN) pueden comunicarse con una red externa (WAN) compartiendo una única dirección IP pública.

## Características Principales

* **Enrutamiento SDN:** Lógica de control centralizada utilizando el controlador POX y el protocolo OpenFlow 1.0.
* **Mecanismo PAT Dinámico:** Traducción de origen (Source NAT) para el tráfico saliente, asignando dinámicamente un pool de 55.001 puertos (comenzando desde el puerto base 10000).
* **Gestión de Flujos:** Instalación proactiva y reactiva de reglas de flujo en el switch Open vSwitch (OVS) con tiempos de expiración (`idle_timeout`) para la liberación y reciclaje automático de puertos.

## Topología de la Red

La simulación consta de tres niveles principales:
* **Plano de Control:** Controlador POX (`127.0.0.1:6633`).
* **Plano de Datos:** 1 Switch central OVS (`s1`) que actúa como pasarela/enrutador.
* **Hosts:**
  * **Red Pública (WAN):** `h1` (IP: `200.0.0.1/24`) conectado al puerto 1.
  * **Red Privada (LAN):** `h2`, `h3` y `h4` (Subred `192.168.1.0/24`) conectados a los puertos 2, 3 y 4 respectivamente.

El switch `s1` asume dos identidades lógicas:
* **Gateway LAN:** `192.168.1.254`
* **IP Pública WAN:** `200.0.0.254`

## Requisitos Previos

* [Mininet](http://mininet.org/)
* [Controlador POX](https://github.com/noxrepo/pox)
* Python

