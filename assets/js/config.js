const guardianOrigin = window.location.hostname === "agente-sa.github.io"
  ? "https://guardiansusverify.squareweb.app"
  : window.location.origin;

window.VERIFICATION_CONFIG = Object.freeze({
  apiBaseUrl: guardianOrigin,
  requestTimeoutMs: 30000
});
