(async () => {
  const registerServiceWorker = async () => {
    const oldRegistration = await navigator.serviceWorker.getRegistration();
    if (oldRegistration) return;
    await navigator.serviceWorker.register("/sw.js", {
      scope: new URL("/", window.location.origin).toString(),
    });
    setTimeout(() => window.location.reload(), 500);
  };

  registerServiceWorker();
})();
