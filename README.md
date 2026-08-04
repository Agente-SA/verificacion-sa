# Verificacion Super Sus SA

Aplicacion independiente que contiene el bot de Discord, la API HTTP de
verificacion y el frontend estatico servido por Guardian SUS en Square Cloud.

## Componentes

- `bot.py`: arranque del bot, sincronizacion de comandos y ciclo de retencion.
- `modules/verificacion.py`: panel, enlaces personales y comandos de staff.
- `api/verification_api.py`: OAuth2 `identify`, callback y evaluación pública.
- `core/database.py`: tablas y consultas exclusivas de verificacion en Neon.
- `core/verification_security.py`: tokens HMAC y hashes de privacidad.
- `core/verification_risk.py`: evaluacion de coincidencias y riesgo.
- `core/vpn_detection.py`: consultas a proxycheck.io e ipapi.is.
- `index.html`, `privacy.html`, `terms.html` y `assets/`: frontend servido por
  el mismo origen HTTPS de la API.

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

### OAuth2 de Discord

La identidad se confirma mediante Authorization Code Grant con el scope mínimo
`identify`. En Discord Developer Portal agrega en **OAuth2 > Redirects** el
valor exacto configurado en `DISCORD_OAUTH_REDIRECT_URI`. `DISCORD_CLIENT_ID`
es el Application ID de Guardian SUS y `DISCORD_CLIENT_SECRET` se obtiene en
**OAuth2 > Client information** mediante **Reset Secret**. El secreto solo debe
existir en Square Cloud; nunca debe aparecer en GitHub Pages ni en el repo.

El parámetro `state` se guarda en PostgreSQL mediante hash, caduca y solo puede
consumirse una vez. Los access tokens OAuth de Discord se descartan después de
consultar `/users/@me` y no se persisten.

`/verificacion_directa usuario:@Miembro` permite al staff enviar por DM una
solicitud alternativa con consentimiento. Al aceptarla, el miembro recibe un
enlace OAuth2 de un solo uso sin depender del formulario inicial. El callback
conserva las comprobaciones de red, VPN, antigüedad, roles e historial, pero no
genera la huella JavaScript que solo existe en el flujo web normal. Si el
miembro tiene los mensajes directos cerrados, el comando informa el problema al
staff y no crea ningún token.

El enlace personal solo controla cuánto tiempo tiene el usuario para comenzar.
Al iniciar, el token pasa a `in_progress` y obtiene una ventana OAuth completa e
independiente. Los reintentos reutilizan esa reserva sin ampliar su vencimiento.
`PUBLIC_VERIFICATION_URL` es opcional: si se omite, Guardian usa automáticamente
el origen de `DISCORD_OAUTH_REDIRECT_URI`.

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
La aceptacion crea una entrega durable `approved_pending_role`; la aprobación
solo se completa cuando Discord confirma el rol. Un reconciliador se ejecuta
al arrancar y cada minuto para recuperar interrupciones. `/metricas` consulta
los resultados del mes UTC que aun se encuentran dentro de la retencion
detallada.

## Desarrollo local

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python bot.py
```

## GitHub Pages opcional

GitHub Pages puede conservarse como copia pública de los documentos, pero los
enlaces personales generados por el bot usan Square Cloud. El token permanece
en el fragmento `#token=...`, que no se envía al servidor en la navegación.

## Square Cloud

1. Importa este repositorio desde GitHub.
2. Selecciona `bot.py` como archivo principal.
3. Asigna al menos 512 MB y el entorno Python recomendado.
4. Inyecta todas las variables de `.env.example`.
5. Activa Publicacion en la Web y asigna un subdominio.
6. Registra `https://SUBDOMINIO.squareweb.app/oauth/callback` como Redirect de
   OAuth2 y usa exactamente esa misma URL en `DISCORD_OAUTH_REDIRECT_URI`.
7. Conserva `HOST=0.0.0.0` y `PORT=80`.
8. Despliega y comprueba `https://SUBDOMINIO.squareweb.app/health`.
9. Abre `https://SUBDOMINIO.squareweb.app/` y comprueba el frontend.

El servicio no inicia si falta PostgreSQL, un secreto o una variable critica.
