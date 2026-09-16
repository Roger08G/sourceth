# Seguridad y limitaciones

## Frontera de confianza

La dirección, la configuración, la salida de RPC, los mensajes de Cast y todos los nombres y
contenidos publicados por el explorador se tratan como datos no confiables. Sourceth no importa,
ejecuta, compila ni instala dependencias del código descargado.

Cast crea archivos antes de que Python pueda inspeccionarlos. Un directorio temporal no es un
sandbox. La versión de Cast debe superar la comprobación de capacidades y la política de contención
de la plataforma antes de usar `cast source -d`. En plataformas donde no pueda garantizarse esa
contención, Sourceth rechaza la descarga real y recomienda ejecutar la herramienta dentro de Linux
o de un contenedor con el directorio de salida como único volumen escribible. La inspección posterior
sigue siendo obligatoria, pero no se presenta como aislamiento preventivo.

La revisión de seguridad usada para la política nativa comprueba que la implementación soportada de
Foundry elimina componentes padre y fuerza rutas absolutas POSIX a ser relativas. Sourceth además
rechaza rutas absolutas, ambos separadores, `..`, enlaces, junctions, archivos especiales, nombres
reservados de Windows, colisiones por `casefold()` y resultados que excedan los límites configurados.
La raíz de salida y todos sus ancestros se revalidan contra symlinks y junctions antes y dentro de
los bloqueos. En Windows, una ruta final de 260 caracteres o más se rechaza antes de publicar.

La allowlist de escritura contiene una sola build: Cast 1.8.3 con commit
`cae51ad458f6abb64852b7709eb784352429825d`. Una versión que coincida solo por número, pero no por
commit, se rechaza. Incluso esa build se bloquea para `cast source` nativo en Windows porque su
normalización de rutas no demuestra contención de prefijos de unidad y UNC.

## Procesos

- Los comandos se construyen como listas y siempre se ejecutan con `shell=False`.
- No se aceptan `.bat` ni `.cmd` como sustitutos del binario.
- Hay límites independientes de tiempo y salida capturada.
- Los procesos se crean en un grupo y se termina el grupo al cancelar o exceder límites.
- Solo se hereda un conjunto reducido de variables necesarias para ejecutar Cast.

En Windows, un bootstrap de Python espera a que el proceso ya pertenezca a un Job Object con
`KILL_ON_JOB_CLOSE` antes de crear Cast; así no existe una ventana entre spawn y asignación. En
POSIX se usa un grupo de procesos propio y se verifica su terminación completa.

El presupuesto de reintentos acota los intentos de Cast y el backoff, y cada intento recibe como
timeout como máximo el presupuesto restante. La terminación segura del grupo puede añadir después
una gracia corta y acotada; el presupuesto no es una promesa de deadline duro que abandone hijos.

Estas medidas no convierten a Cast en código no confiable: el usuario debe instalarlo desde una
fuente oficial y verificar su procedencia.

## Secretos

La API key y la URL RPC se suministran al hijo como variables de entorno, nunca como argumentos.
Sourceth redacta sus valores y URLs con rutas o consultas sensibles de logs, errores y manifiestos.
`.env` se lee solo desde la ruta exacta indicada (por defecto `./.env`), sin búsqueda ascendente ni
recursiva y sin sobrescribir variables ya presentes en el proceso. Antes de fusionar valores se
rechaza cualquier `.env` situado bajo la estructura de fuentes de una revisión de Sourceth, aunque
ese archivo intente cambiar el propio directorio de salida o los nombres de variables secretas.

Las variables de entorno no son invisibles para un administrador del sistema ni para procesos con
privilegios suficientes. Esta herramienta reduce exposiciones accidentales; no crea una frontera
frente al administrador del equipo.

## Salida de red del explorador

Cada `cast source` recibe `HTTP_PROXY`, `HTTPS_PROXY` y `ALL_PROXY` apuntando a una guardia CONNECT
efímera en `127.0.0.1`, además de un `NO_PROXY` centinela que impide recuperar excepciones proxy del
sistema. El listener es exclusivo en Windows, exige una credencial aleatoria y solo conecta con el
host y puerto HTTPS de `explorer_api_url`. Los intentos autenticados a otro origen se bloquean antes
de abrir TLS y cancelan la descarga.

La guardia limita conexiones, cabeceras y tiempos, y no registra URLs completas. Esta medida evita
que la API key acompañe una redirección cross-origin en la build revisada. No protege frente a Cast
malicioso, a un administrador local ni a una alteración del sistema operativo; por eso una build
desconocida no puede escribir fuentes.

La resolución DNS del origen permitido depende del sistema operativo y no ofrece en Python un
deadline duro cancelable. Los sockets sí tienen timeout y los workers son daemon; una resolución
del sistema atascada puede retrasar su salida, pero no amplía el origen permitido ni entrega la API
key al resolvedor DNS.

## Qué prueba el resultado

- `verification.provider_provenance = declared_by_explorer`: Cast recibió alguna fuente
  declarada por el explorador.
- `contracts[].source_provenance.provider_declared = published_source`: ese contrato concreto
  dispone de fuentes publicadas.
- Los SHA-256 prueban integridad posterior de los archivos locales.
- El Keccak del runtime identifica el bytecode observado por RPC.
- `independent_recompilation = not_performed`: Sourceth no recompila ni demuestra equivalencia
  entre las fuentes y el bytecode.

Una descarga completa no garantiza que sea el repositorio original del desarrollador, que las
fuentes compilen, ni que el contrato sea seguro. `--block` fija el estado consultado por RPC; el
explorador puede devolver únicamente su publicación actual, no fuentes históricas.

Las lecturas on-chain usan EIP-1898 por hash cuando el nodo lo admite. Sourceth solo degrada a la
referencia numérica si la respuesta atribuye inequívocamente el rechazo al objeto de bloque y, antes
de publicar, relee ese número y exige que conserve el hash observado. Un error ambiguo falla cerrado.

## Proxies

La detección se limita a los slots EIP-1967, beacon EIP-1967 y el bytecode canónico ERC-1167. Un
slot compatible es evidencia de un candidato, no prueba universal de la semántica del contrato.
Sourceth no distingue Transparent de UUPS solo por el slot y no busca diamonds, proxies propios ni
variantes heurísticas. Si no encuentra un patrón soportado informa
`no_supported_pattern_detected`; no afirma que la dirección no sea un proxy.

## Alcance deliberadamente excluido

No hay enumeración masiva o de protocolos, explotación, decompilación, auditoría automática,
transacciones, firmas, wallets, claves privadas, compilación, forks, servidor, workers permanentes
ni instalación de dependencias de contratos.

## Validación efectuada

La interfaz se comprobó offline con el ZIP oficial de Foundry 1.8.3 para Windows x86-64:

- SHA-256 del ZIP, coincidente con el digest publicado en la release:
  `e4d7302fa708423c8799f5a229dfecef311cfd68b046ce782788096318946304`.
- SHA-256 de `cast.exe`: `4695e393bc89e5eb4c64464c2e08cefafa25a09786b6db55ff48f38bacfe6764`.
- Versión observada: 1.8.3; commit
  `cae51ad458f6abb64852b7709eb784352429825d`; perfil `dist`.
- `cast source --help` y `cast rpc --help` confirmaron los argumentos y variables usados.

Esta comprobación no fue una descarga real. No se usaron una API key ni un RPC de producción y no
se afirma funcionamiento contra mainnet. La integración real permanece opt-in.

## Referencias normativas

- [EIP-55](https://eips.ethereum.org/EIPS/eip-55)
- [EIP-1967](https://eips.ethereum.org/EIPS/eip-1967)
- [EIP-1167](https://eips.ethereum.org/EIPS/eip-1167)
- [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898)
- [Foundry Cast](https://getfoundry.sh/cast/overview)
- [Cast source](https://getfoundry.sh/reference/cast/source/)
