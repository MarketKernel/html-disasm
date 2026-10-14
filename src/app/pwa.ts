/**
 * The installed app (the PWA of build/pages/): registers its service worker
 * (src/pwa/sw.js), which keeps the page for offline use and brings each new
 * deploy in by itself.
 *
 * The same code runs in the single file, where it does nothing: only the PWA's
 * page carries <meta name="service-worker">, put in by build.mjs.
 */
export function startServiceWorker(): void {
  const script = document.querySelector<HTMLMetaElement>('meta[name="service-worker"]')?.content;
  if (!script || !('serviceWorker' in navigator)) return;
  const register = (): void => {
    // Without a worker the page still works; it only does not open offline.
    navigator.serviceWorker.register(script).catch(() => undefined);
  };
  if (document.readyState === 'complete') register();
  else addEventListener('load', register, { once: true });
}
