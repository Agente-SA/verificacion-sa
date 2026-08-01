(function () {
  "use strict";

  const config = window.VERIFICATION_CONFIG || {};
  const verificationPanel = document.getElementById("verification-panel");
  const successPanel = document.getElementById("success-panel");
  const consentInput = document.getElementById("privacy-consent");
  const startButton = document.getElementById("start-verification");
  const linkWarning = document.getElementById("link-warning");
  const statusMessage = document.getElementById("status-message");

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
    const fragment = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : window.location.hash;
    return new URLSearchParams(fragment).get("token") || "";
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
      const response = await fetch(`${apiBaseUrl}/api/verification/submit`, {
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

      window.history.replaceState(null, "", window.location.pathname);
      verificationPanel.classList.add("is-hidden");
      successPanel.classList.remove("is-hidden");
      successPanel.focus?.();
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

  function setLoading(isLoading) {
    startButton.disabled = isLoading || !consentInput.checked;
    consentInput.disabled = isLoading;
    startButton.lastChild.textContent = isLoading
      ? " Procesando..."
      : " Iniciar verificación";
  }

  function showStatus(message) {
    statusMessage.textContent = message;
    statusMessage.classList.remove("is-hidden");
  }
}());
