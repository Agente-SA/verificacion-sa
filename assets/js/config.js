const guardianOrigin = window.location.hostname === "agente-sa.github.io"
  ? "https://guardian-sus-verificacion-api.squareweb.app"
  : window.location.origin;

window.VERIFICATION_CONFIG = Object.freeze({
  apiBaseUrl: guardianOrigin,
  requestTimeoutMs: 30000
});
