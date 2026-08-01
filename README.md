# Verificación SA - Frontend

Interfaz estática del sistema de verificación de la comunidad Super Sus SA.

## Responsabilidad del repositorio

Este repositorio contiene únicamente archivos públicos para GitHub Pages:

- Aviso de privacidad y consentimiento.
- Lectura del token temporal desde el fragmento de la URL.
- Recopilación de señales técnicas limitadas después del consentimiento.
- Envío de la solicitud a la API de Square Cloud.
- Pantalla final genérica.

No contiene secretos, conexión directa con PostgreSQL, lógica de riesgo ni credenciales de Discord.

## Configuración local

La URL pública de la API se define en `assets/js/config.js`:

```js
window.VERIFICATION_CONFIG = Object.freeze({
  apiBaseUrl: "https://api.example.com",
  requestTimeoutMs: 15000
});
```

La URL permanecerá vacía hasta desplegar la API en Square Cloud.

## Prueba visual

Abre `index.html` con un token de prueba en el fragmento:

```text
index.html#token=token_de_prueba_1234567890
```

La interfaz permitirá revisar el consentimiento, pero no enviará datos mientras `apiBaseUrl` esté vacío.

## Publicación posterior

Cuando el repositorio remoto esté creado:

```bash
git branch -M main
git remote add origin URL_DEL_REPOSITORIO
git add .
git commit -m "Crea frontend inicial de verificacion"
git push -u origin main
```

Después se habilitará GitHub Pages desde la rama `main` y la carpeta raíz.
