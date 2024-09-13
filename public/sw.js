self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(clients.claim());
});

/**
 * @param {string} base64
 */
function base64ToArrayBuffer(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

async function fetchCertificate() {
  const cert = await fetch("/webtransportify/certificates/%40");
  if (!cert.ok) throw new Error("Failed to fetch certificate");
  const json = await cert.json();
  return json;
}

let certificatePromise = fetchCertificate();

/**
 * @param {Request} request
 * @returns ReadableStream
 */
function encodeHttpRequest(request) {
  const url = new URL(request.url);
  const host = url.host;
  const pathname = url.pathname || "/";
  const headers = new Headers(request.headers);
  headers.set("Host", host);
  const httpHeaders = `${request.method} ${pathname} HTTP/1.1\r\n${Array.from(
    headers
  )
    .map(([name, value]) => `${name}: ${value}`)
    .join("\r\n")}\r\n\r\n`;

  const transformer = new TransformStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(httpHeaders));
    },
    transform(chunk, controller) {
      controller.enqueue(chunk);
    },
  });

  const body = request.body ? request.body : new ReadableStream();

  return body.pipeThrough(transformer);
}

/**
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeout
 * @param {string} message
 * @returns {Promise<T>}
 */
function timeoutWrapper(promise, timeout, message = "Timeout") {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(message));
    }, timeout);
    promise.then(resolve, reject).finally(() => clearTimeout(timer));
  });
}

/**
 * @param {ReadableStream<ArrayBuffer>} readable
 */
async function decodeHttpResponse(readable) {
  const reader = readable.getReader();

  const decoder = new TextDecoder();
  let headerChunks = "";
  let rest = new Uint8Array();
  while (true) {
    const { value, done } = await timeoutWrapper(reader.read(), 5000);
    if (done) break;
    headerChunks += decoder.decode(value, { stream: true });
    const emptyLineIndex = headerChunks.indexOf("\r\n\r\n");
    if (emptyLineIndex !== -1) {
      headerChunks = headerChunks.slice(0, emptyLineIndex);
      rest = value.slice(emptyLineIndex + 4);
      break;
    }
  }

  const [statusLine, ...headerLines] = headerChunks.split("\r\n");
  const [, status, statusText] = statusLine.match(/HTTP\/1.1 (\d+) (.+)/);
  const headers = new Headers(
    Object.fromEntries(headerLines.map((line) => line.split(": ", 2)))
  );

  const contentLength = parseInt(headers.get("Content-Length") ?? "0");
  let lengthRead = rest.length;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(rest);
    },
    async pull(controller) {
      const { value, done } = await reader.read();
      if (done) {
        controller.close();
        return;
      }
      controller.enqueue(value);
      lengthRead += value.length;
      if (lengthRead >= contentLength) controller.close();
    },
  });

  const response = new Response(lengthRead === contentLength ? rest : body, {
    status: parseInt(status),
    statusText,
    headers,
  });
  return response;
}

/**
 * @param {Request} request
 * @param {{ url: string, serverCertificateHashes: string[] }} options
 * @returns {Promise<Response>}
 */
async function fetchThroughWebTransport(
  request,
  { url, serverCertificateHashes }
) {
  const cache = await caches.open("webtransportify");
  const cachedResponse = await cache.match(request);
  if (cachedResponse) return cachedResponse;

  if (!("WebTransport" in self)) {
    return new Response("Safari and old browsers are not supported", {
      status: 502,
      statusText: "Bad Gateway",
    });
  }

  const wt = new WebTransport(url, {
    serverCertificateHashes: serverCertificateHashes.map((hash) => ({
      algorithm: "sha-256",
      value: base64ToArrayBuffer(hash),
    })),
  });

  try {
    await timeoutWrapper(wt.ready, 10000, "WebTransport timeout");

    const stream = await wt.createBidirectionalStream();
    encodeHttpRequest(request).pipeTo(stream.writable);
    const response = await decodeHttpResponse(stream.readable);
    if (
      response.ok &&
      !response.headers.get("content-type")?.startsWith("text/html")
    )
      cache.put(request, response.clone());
    return response;
  } catch (e) {
    return new Response(e.message, {
      status: 502,
      statusText: "Bad Gateway",
    });
  }
}

/**
 * @param {Request} request
 * @returns {Promise<Response>}
 */
async function handleFetch(request) {
  let certObj = await certificatePromise.catch(() => null);
  if (!certObj) {
    return new Response("Domain not found", {
      status: 404,
      statusText: "Not Found",
    });
  }

  const {
    url: webTransportUrl,
    certificate_hash,
    alt_certificate_hash,
  } = certObj;
  const serverCertificateHashes = alt_certificate_hash
    ? [certificate_hash, alt_certificate_hash]
    : [certificate_hash];

  return timeoutWrapper(
    fetchThroughWebTransport(request, {
      url: webTransportUrl,
      serverCertificateHashes,
    }),
    15000,
    "Request timeout"
  ).catch((e) => {
    return new Response(e.message, {
      status: 502,
      statusText: "Bad Gateway",
    });
  });
}

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (
    url.origin !== self.location.origin ||
    url.href === self.location.href ||
    url.pathname.startsWith("/webtransportify/")
  )
    return;

  event.respondWith(handleFetch(event.request));
});
