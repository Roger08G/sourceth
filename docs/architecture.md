# Arquitectura

Sourceth tiene un único caso de uso: obtener las fuentes que un explorador publica para una
dirección EVM mediante `cast source`. No descubre contratos, no compila, no audita y no ejecuta
el código descargado.

```text
CLI / API Python
      |
      v
SourceDownloader (orquestación síncrona)
      |--------------------|----------------------|
      v                    v                      v
CastAdapter           ProxyResolver          RevisionStore
      |                    |                      |
      +--> EgressGuard     |                      v
      |    (solo source)   |               manifiesto + caché
      v                    |
ProcessRunner <------------+
      |
      v
Foundry Cast (RPC y explorador configurado)
```

## Responsabilidades

- `cli.py`: convierte argumentos en `DownloadRequest` y presenta resultados. Es el único módulo
  que traduce excepciones y estados a códigos de salida.
- `service.py`: valida y orquesta una descarga. No conoce `argparse` ni termina procesos Python.
- `validation.py`: funciones puras para direcciones, bloques y respuestas hexadecimales.
- `adapters/process.py`: único punto que crea procesos externos.
- `adapters/cast.py`: comprueba las capacidades de Cast, construye `argv`, traduce JSON-RPC y
  clasifica fallos del proveedor.
- `adapters/egress.py`: restringe cada descarga de fuentes al origen HTTPS configurado mediante
  un proxy CONNECT local autenticado y de un solo uso.
- `proxy.py`: resuelve solo EIP-1967, beacon EIP-1967 y ERC-1167 canónico, con límites y ciclos.
- `store.py`: staging, inspección de fuentes, caché, bloqueo y publicación atómica.
- `manifest.py`: convierte el resultado tipado en JSON versionado y determinista.
- `config.py`: combina defaults, TOML, `.env`, entorno y opciones explícitas sin exponer secretos.

## Flujo de una ejecución

1. Se valida la entrada sin red.
2. Se abre un snapshot nuevo de la versión y capacidades de Cast para ese `fetch`; sus llamadas
   internas lo reutilizan, pero la siguiente ejecución vuelve a comprobar el binario.
3. En modo RPC se comprueba el chain ID, se fija un bloque y se lee el bytecode. Las lecturas de
   estado prefieren la referencia EIP-1898 por hash; si el nodo la rechaza inequívocamente, se usa
   el número observado para el resto de esa ejecución.
4. Si se solicitó, se resuelven relaciones de proxy contra ese mismo bloque.
5. Cada dirección se reutiliza desde una caché íntegra o se descarga una sola vez a staging.
6. Se inspecciona el árbol y se calculan los hashes sin modificar su contenido.
7. En modo RPC se vuelve a comprobar el hash del número de bloque; esto también protege la ruta de
   compatibilidad por número frente a reorganizaciones silenciosas.
8. Solo con un estado coherente se actualiza la caché; una inconsistencia queda fuera de ella.
9. Se crea el manifiesto, se publica la revisión y se sustituye `latest.json` bajo bloqueo.

La ejecución es deliberadamente síncrona. Para una dirección, paralelizar añadiría estados,
reintentos y consumo del proveedor sin mejorar de forma material la corrección.

## Extensión de redes

El registro de redes es un dato inyectable. Añadir otra red requiere declarar su chain ID, nombre y
proveedor; el servicio no contiene ramas específicas por red. Que una red sea EVM no implica que
Etherscan ni el plan de la API la soporten.

## Persistencia

```text
downloads/
├── .sourceth/
│   ├── cache/k-HASH/
│   ├── locks/
│   └── staging/
└── CHAIN_ID/ROOT_ADDRESS/
    ├── latest.json
    └── runs/RUN_ID/
        ├── manifest.json
        └── contracts/ADDRESS/
            ├── runtime-bytecode.hex
            └── sources/...
```

`latest.json` distingue la última ejecución de la última ejecución completa. Una revisión
parcial no se presenta como sustituta equivalente de una completa.

La clave compacta de caché deriva por SHA-256 del proveedor, su identidad de endpoints completa,
chain ID y dirección. El inventario vuelve a comparar esos valores completos: el nombre abreviado
no es la autoridad de identidad. El manifiesto persiste el hash de identidad y solo los orígenes
de los endpoints, nunca sus rutas, consultas o credenciales.
