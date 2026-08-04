(function () {
  "use strict";

  const config = window.VERIFICATION_CONFIG || {};
  const MAX_START_ATTEMPTS = 2;
  const START_RETRY_DELAY_MS = 1800;
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
    const signals = collectLimitedSignals();

    try {
      for (let attempt = 1; attempt <= MAX_START_ATTEMPTS; attempt += 1) {
        try {
          const result = await requestOAuthStart(
            apiBaseUrl,
            token,
            signals
          );

          if (
            result.status === "completed" &&
            isSafeResultUrl(result.result_url)
          ) {
            window.location.replace(result.result_url);
            return;
          }
          if (!isDiscordAuthorizationUrl(result.authorization_url)) {
            const invalidUrlError = new Error(
              "invalid_oauth_authorization_url"
            );
            invalidUrlError.code = "invalid_oauth_authorization_url";
            throw invalidUrlError;
          }

          window.history.replaceState(null, "", window.location.pathname);
          window.location.assign(result.authorization_url);
          return;
        } catch (error) {
          if (!isRetriableStartError(error) || attempt === MAX_START_ATTEMPTS) {
            throw error;
          }
          showStatus(
            "La conexión está tardando más de lo habitual. " +
            "Realizaremos un segundo intento automáticamente..."
          );
          await delay(START_RETRY_DELAY_MS);
        }
      }
    } catch (error) {
      showStartError(error);
    } finally {
      setLoading(false);
    }
  }

  async function requestOAuthStart(apiBaseUrl, token, signals) {
    const controller = new AbortController();
    const timeout = window.setTimeout(
      () => controller.abort(),
      Number(config.requestTimeoutMs) || 30000
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
          signals
        }),
        signal: controller.signal
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) {
        const requestError = new Error(
          result.code || "verification_request_failed"
        );
        requestError.code = result.code || "verification_request_failed";
        requestError.status = response.status;
        throw requestError;
      }
      return result;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function isRetriableStartError(error) {
    return error?.name === "AbortError" ||
      error instanceof TypeError ||
      error?.code === "temporarily_unavailable" ||
      Number(error?.status) >= 500;
  }

  function showStartError(error) {
    if (error?.code === "invalid_or_expired_link") {
      showStatus(
        "Este enlace ya venció o fue utilizado. Regresa a Discord y genera " +
        "uno nuevo."
      );
      return;
    }
    if (error?.code === "too_many_requests") {
      showStatus(
        "Hay varias solicitudes recientes desde esta conexión. Espera unos " +
        "minutos y vuelve a presionar el botón; no necesitas generar otro " +
        "enlace mientras este siga vigente."
      );
      return;
    }
    if (error?.code === "membership_required") {
      showStatus(
        "No pudimos confirmar tu membresía en el servidor. Regresa a Discord " +
        "y comprueba que continúas dentro de la comunidad."
      );
      return;
    }
    if (error?.code === "invalid_request") {
      showStatus(
        "No pudimos validar los datos de esta solicitud. Regresa a Discord y " +
        "genera un enlace nuevo."
      );
      return;
    }
    showStatus(
      "El servicio está tardando más de lo habitual. Espera unos segundos y " +
      "vuelve a presionar Iniciar verificación; puedes conservar este enlace " +
      "mientras no haya vencido."
    );
  }

  function delay(milliseconds) {
    return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
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
