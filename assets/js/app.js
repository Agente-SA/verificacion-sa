(function () {
  "use strict";

  const config = window.VERIFICATION_CONFIG || {};
  const verificationPanel = document.getElementById("verification-panel");
  const successPanel = document.getElementById("success-panel");
  const consentInput = document.getElementById("privacy-consent");
  const startButton = document.getElementById("start-verification");
  const linkWarning = document.getElementById("link-warning");
  const statusMessage = document.getElementById("status-message");
  const successTitle = document.getElementById("success-title");
  const resultMessage = document.getElementById("result-message");
  const resultNote = document.getElementById("result-note");

  const oauthResult = readFragmentValue("result");
  if (["received", "rejected", "retry"].includes(oauthResult)) {
    showOAuthResult(oauthResult);
    return;
  }

  const token = readToken();
  const tokenIsValid = /^[A-Za-z0-9._~-]{20,2048}$/.test(token);

  if (!tokenIsValid) {
    linkWarning.classList.remove("is-hidden");
    consentInput.disabled = true;
  }

  consentInput.addEventListener("change", function () {
    startButton.disabled = !tokenIsValid || !consentInput.checked;
  });

  startButton.addEventListener("click", submitVerification);

  function readToken() {
    return readFragmentValue("token");
  }

  function readFragmentValue(name) {
    const fragment = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : window.location.hash;
    return new URLSearchParams(fragment).get(name) || "";
  }

  function showOAuthResult(result) {
    window.history.replaceState(null, "", window.location.pathname);
    verificationPanel.classList.add("is-hidden");
    successPanel.classList.remove("is-hidden");

    if (result === "rejected") {
      successTitle.textContent = "Verificación no aprobada";
      resultMessage.textContent =
        "Vuelve a Discord para consultar el resultado y las opciones de soporte.";
      resultNote.textContent = "Ya puedes cerrar esta página.";
    } else if (result === "retry") {
      successTitle.textContent = "No pudimos completar la solicitud";
      resultMessage.textContent =
        "Regresa a Discord, genera un enlace nuevo e inténtalo más tarde.";
      resultNote.textContent = "Ningún acceso fue concedido.";
    }
    successPanel.focus?.();
  }

  function collectLimitedSignals() {
    const userAgentData = navigator.userAgentData || null;
    return {
      signalVersion: 1,
      language: navigator.language || "unknown",
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
      userAgent: navigator.userAgent || "unknown",
      platform: userAgentData?.platform || navigator.platform || "unknown",
      mobile: userAgentData?.mobile ?? isProbablyMobile(),
      deviceClass: deviceClass(),
      touchSupport: navigator.maxTouchPoints > 0
    };
  }

  function isProbablyMobile() {
    return /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent || "");
  }

  function deviceClass() {
    const width = Math.min(window.screen.width, window.screen.height);
    if (width < 600) return "phone";
    if (width < 1024) return "tablet";
    return "desktop";
  }

  async function submitVerification() {
    if (!tokenIsValid || !consentInput.checked) return;

    const apiBaseUrl = String(config.apiBaseUrl || "").replace(/\/$/, "");
    if (!apiBaseUrl) {
      showStatus(
        "La conexión con el sistema de verificación todavía no está habilitada. " +
        "Vuelve a intentarlo cuando el bot publique el enlace oficial."
      );
      return;
    }

    setLoading(true);
    showStatus("Enviando tu solicitud de forma segura...");

    const controller = new AbortController();
    const timeout = window.setTimeout(
      () => controller.abort(),
      Number(config.requestTimeoutMs) || 15000
    );

    try {
      const response = await fetch(`${apiBaseUrl}/api/oauth/start`, {
        method: "POST",
        mode: "cors",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          token,
          consent: true,
          signals: collectLimitedSignals()
        }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error("verification_request_failed");
      const result = await response.json();

      if (result.status === "completed" && isSafeResultUrl(result.result_url)) {
        window.location.replace(result.result_url);
        return;
      }
      if (!isDiscordAuthorizationUrl(result.authorization_url)) {
        throw new Error("invalid_oauth_authorization_url");
      }

      window.history.replaceState(null, "", window.location.pathname);
      window.location.assign(result.authorization_url);
    } catch (error) {
      showStatus(
        "No pudimos completar la solicitud en este momento. Regresa a Discord, " +
        "genera un enlace nuevo e inténtalo otra vez."
      );
    } finally {
      window.clearTimeout(timeout);
      setLoading(false);
    }
  }

  function isDiscordAuthorizationUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === "https:" &&
        url.hostname === "discord.com" &&
        url.pathname === "/oauth2/authorize";
    } catch (_error) {
      return false;
    }
  }

  function isSafeResultUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === "https:" &&
        url.origin === window.location.origin &&
        url.hash.startsWith("#result=");
    } catch (_error) {
      return false;
    }
  }

  function setLoading(isLoading) {
    startButton.disabled = isLoading || !consentInput.checked;
    consentInput.disabled = isLoading;
    startButton.lastChild.textContent = isLoading
      ? " Conectando con Discord..."
      : " Iniciar verificación";
  }

  function showStatus(message) {
    statusMessage.textContent = message;
    statusMessage.classList.remove("is-hidden");
  }
}());
