# RaceCoach AI — aplicación móvil instalable (PWA)

Esta es la versión centrada en móvil. Se abre como una aplicación web progresiva (PWA) y se puede añadir a la pantalla de inicio en iPhone y Android cuando esté publicada en un dominio HTTPS. Incluye una interfaz móvil con Inicio, Carreras, Progreso y Cuenta; el frontend consulta el backend OAuth de este mismo proyecto y no contiene secretos OAuth.

## Lo que incluye

- Interfaz responsive diseñada para móvil.
- Manifiesto PWA y service worker para instalación y caché básica de la interfaz.
- Pantalla privada de acceso a RaceCoach AI, separada de la cuenta de iRacing.
- OAuth Authorization Code + PKCE, validación de `state` de un solo uso y tokens cifrados con Fernet en el backend.
- Endpoints iniciales de perfil, estadísticas, recapitulación, carreras recientes y mejores marcas, con caché local.
- Estado de conexión, sincronización manual, historial y diagnóstico básico de recursos importados.
- Los datos de carreras no se inventan: si la API no devuelve datos o el formato no coincide, la interfaz lo indica.

## Limitación importante: no se puede instalar desde el ZIP y conectar directamente sin publicar el backend

El ZIP es el proyecto de la aplicación, no una app ya publicada en App Store/Google Play. Para instalarla como PWA en el teléfono hace falta desplegar este proyecto en un servidor HTTPS. El navegador móvil no puede ejecutar el backend Python desde el ZIP. Además, iRacing debe aceptar el Client ID y la Redirect URI pública debe estar registrada exactamente en ese cliente.

No publiques el servidor hasta configurar contraseña de la app, secreto de sesión, credenciales OAuth y almacenamiento persistente. No uses un servidor sin autenticación: el historial y las rutas de sincronización son privados.

## Configuración para el despliegue

1. Despliega el proyecto como servicio Python/Docker en un proveedor que admita HTTPS y almacenamiento persistente. El `Dockerfile` incluido es una base para ese despliegue.
2. Configura todas las variables de `.env.example` en el panel de variables secretas del proveedor; no subas un `.env` real al repositorio.
3. Cambia `IRACING_REDIRECT_URI` por `https://TU-DOMINIO/oauth/callback` y registra exactamente esa misma URI en la configuración de tu Client ID de iRacing.
4. Define `RACECOACH_APP_PASSWORD` como una contraseña larga y exclusiva para RaceCoach AI (no es tu contraseña de iRacing).
5. Genera `RACECOACH_SESSION_SECRET` con `python -c "import secrets; print(secrets.token_urlsafe(48))"` y configura `RACECOACH_COOKIE_SECURE=true`.
6. Configura `RACECOACH_DB_PATH` dentro de un volumen persistente, por ejemplo `/data/racecoach.db`. Conserva el mismo `RACECOACH_FERNET_KEY` de la integración original: genera una clave Fernet con `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` y añade la variable `RACECOACH_FERNET_KEY` a las variables secretas.
7. Abre la URL HTTPS desde el móvil e inicia sesión en RaceCoach AI. Pulsa **Vincular iRacing**; se abrirá el dominio oficial para autorizar la cuenta. Después pulsa **Sincronizar**.
8. Para instalar en iPhone: abre la URL en Safari → botón Compartir → **Añadir a pantalla de inicio**. En Android: abre la URL en Chrome → menú → **Instalar aplicación** o **Añadir a pantalla de inicio**.

## OAuth y seguridad

- RaceCoach AI no pide la contraseña de iRacing; el login se realiza en el dominio oficial de iRacing.
- Los tokens se almacenan cifrados en el servidor, no en localStorage del móvil.
- El acceso a la app se protege con una contraseña propia y una cookie HTTP-only, SameSite=Lax, con Secure activado por defecto.
- Mantén HTTPS, los secretos fuera del código y el disco de base de datos privado.
- Esta versión es un punto de partida para una sola persona, no una plataforma multiusuario auditada. Antes de abrirla al público hacen falta revisión de seguridad, límites de intentos de login, copias de seguridad y observabilidad.
- Los endpoints y campos de la Data API de iRacing pueden cambiar o no estar habilitados para todas las cuentas. La primera sincronización real es la prueba definitiva; los errores se devuelven por recurso.

## Desarrollo local

Requiere Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
# Configura las variables de entorno indicadas arriba y arranca:
uvicorn app:app --host 127.0.0.1 --port 8765
```

Para probar en local por HTTP, solo en desarrollo, puedes usar `RACECOACH_COOKIE_SECURE=false`; no lo uses en producción. La Redirect URI debe coincidir exactamente con la registrada en iRacing.

## Documentación oficial

- https://oauth.iracing.com/oauth2/book/introduction.html
- https://oauth.iracing.com/oauth2/book/authorization_code_flow.html
- https://oauth.iracing.com/oauth2/book/data_api_workflow.html
