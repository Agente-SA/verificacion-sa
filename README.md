# Verificacion Super Sus SA

Aplicacion independiente que contiene el bot de Discord, la API HTTP de
verificacion y el frontend estatico publicado mediante GitHub Pages.

## Componentes

- `bot.py`: arranque del bot, sincronizacion de comandos y ciclo de retencion.
- `modules/verificacion.py`: panel, enlaces personales y comandos de staff.
- `api/verification_api.py`: endpoint publico consumido por el frontend.
- `core/database.py`: tablas y consultas exclusivas de verificacion en Neon.
- `core/verification_security.py`: tokens HMAC y hashes de privacidad.
- `core/verification_risk.py`: evaluacion de coincidencias y riesgo.
- `core/vpn_detection.py`: consultas a proxycheck.io e ipapi.is.
- `index.html`, `privacy.html` y `assets/`: frontend de GitHub Pages.

## Intents y permisos

El bot solo activa el intent estandar `guilds`. Los intents privilegiados
`members`, `message_content` y `presences` deben permanecer desactivados en el
codigo y en Discord Developer Portal.

Permisos de servidor requeridos:

- View Channels
- Send Messages
- Embed Links
- Read Message History
- Manage Roles
- Use Application Commands

El rol del bot debe estar por encima del rol configurado en
`VERIFIED_ROLE_ID`.

## Variables de entorno

Square Cloud debe inyectar las variables; no se debe subir un archivo `.env`.
La lista completa se encuentra en `.env.example`.

La URL de Neon puede copiarse completa. La aplicacion retira automaticamente
`channel_binding`, que no es una opcion de conexion reconocida por `asyncpg`, y
conserva `sslmode=require`.

`STAFF_ROLE_IDS` acepta uno o varios IDs separados por comas. Esos roles
pueden resolver revisiones manuales y usar `/metricas`; el propietario del
servidor tambien conserva acceso. Para que Discord muestre la mencion en una
revision, al menos uno de esos roles debe ser mencionable por el bot.

Los secretos se generan por separado:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

No reutilices `TOKEN_SECRET`. Los hashes de red admiten una rotacion gradual:

1. Conserva la clave anterior en `IP_HASH_SECRET_PREVIOUS`.
2. Coloca la clave nueva en `IP_HASH_SECRET`.
3. Incrementa `IP_HASH_SECRET_VERSION`.
4. Retira la clave anterior cuando haya expirado la retencion historica que
   fue creada con ella.

`TRUSTED_PROXY_CIDRS` limita quien puede aportar `CF-Connecting-IP` y
`CF-IPCountry`. El valor de ejemplo admite loopback y redes privadas usadas
normalmente entre el proxy y la aplicacion. Si Square Cloud cambia esa ruta,
debe agregarse exclusivamente el CIDR confirmado por el proveedor; nunca se
debe usar `0.0.0.0/0` ni `::/0`.

## Decisiones y revision

- Riesgo menor de 30: aprobacion automatica.
- Riesgo de 30 a 64: revision manual persistente en el canal de staff.
- Riesgo de 65 o mas: rechazo automatico.
- Un proveedor VPN positivo envia a revision; dos positivos rechazan.
- Si ambos proveedores VPN fallan, no se decide y se solicita otro intento.

Las revisiones conservan botones de Aceptar y Rechazar despues de reinicios.
Solo la aceptacion otorga el rol. `/metricas` consulta los resultados del mes
UTC que aun se encuentran dentro de la retencion detallada.

## Desarrollo local

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python bot.py
```

## GitHub Pages

Publica la rama `main` desde la carpeta raiz. El token permanece en el
fragmento `#token=...`, que no se envia a GitHub Pages.

La URL publica de Square Cloud se configura en `assets/js/config.js`.

## Square Cloud

1. Importa este repositorio desde GitHub.
2. Selecciona `bot.py` como archivo principal.
3. Asigna al menos 512 MB y el entorno Python recomendado.
4. Inyecta todas las variables de `.env.example`.
5. Activa Publicacion en la Web y asigna un subdominio.
6. Conserva `HOST=0.0.0.0` y `PORT=80`.
7. Despliega y comprueba `https://SUBDOMINIO.squareweb.app/health`.
8. Actualiza `assets/js/config.js` con ese origen HTTPS y vuelve a publicar
   GitHub Pages.

El servicio no inicia si falta PostgreSQL, un secreto o una variable critica.
