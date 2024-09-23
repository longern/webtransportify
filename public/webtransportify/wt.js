(async () => {
  const registerServiceWorker = async () => {
    if (!("WebTransport" in window)) {
      window.location.href = "/webtransportify/403.html";
      return;
    }

    const oldRegistration = await navigator.serviceWorker.getRegistration();
    if (oldRegistration) return;
    await navigator.serviceWorker.register("/sw.js", {
      scope: new URL("/", window.location.origin).toString(),
    });
    setTimeout(() => window.location.reload(), 500);
  };

  registerServiceWorker();
})();
