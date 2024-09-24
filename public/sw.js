const DANGEROUSLY_STORE_HTTPONLY_COOKIES = false;

let basicAuthTokens = {};

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(clients.claim());
});

/** @param {string} base64 */
function base64ToArrayBuffer(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

/** @param {string} str */
function lowerCaseFirstLetter(str) {
  return str ? str.charAt(0).toLowerCase() + str.slice(1) : "";
}

function createCertificateFetcher() {
  const certificate = { current: null };

  return Object.assign(
    async () => {
      if (certificate.current) return certificate.current;

      const cert = await fetch(
        new URL(
          `/webtransportify/certificates/${encodeURIComponent("@")}`,
          self.location.origin
        )
      );
      if (!cert.ok) throw new Error("Failed to fetch certificate");
      /** @type {{ url: string, certificate_hash: string, alt_certificate_hash?: string }} */
      const json = await cert.json();
      certificate.current = json;
      return json;
    },
    {
      reset() {
        certificate.current = null;
      },
    }
  );
}

const certificateFetcher = createCertificateFetcher();

/**
 * @param {Request} request
 * @returns ReadableStream<ArrayBuffer>
 */
function encodeHttpRequest(request) {
  const url = new URL(request.url);
  const host = url.host;
  const pathname = url.pathname;
  const headers = new Headers(request.headers);

  headers.set("Host", host);
  if (url.username)
    basicAuthTokens[url.origin] = `Basic ${btoa(
      `${url.username}:${url.password}`
    )}`;
  if (!headers.has("Authorization") && basicAuthTokens[url.origin])
    headers.set("Authorization", basicAuthTokens[url.origin]);

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

function decodeChunkedTransformer() {
  const decoder = new TextDecoder();
  let buffer = new Uint8Array();

  return new TransformStream({
    transform(chunk, controller) {
      const newBuffer = new Uint8Array(buffer.length + chunk.length);
      newBuffer.set(buffer);
      newBuffer.set(chunk, buffer.length);
      buffer = newBuffer;

      while (true) {
        const newLineIndex = buffer.findIndex(
          (byte, index) => byte === 0x0d && buffer[index + 1] === 0x0a
        );
        if (newLineIndex === -1) break;

        const chunkSize = parseInt(
          decoder.decode(buffer.slice(0, newLineIndex)),
          16
        );
        if (isNaN(chunkSize)) {
          controller.error(new Error("Invalid chunk size"));
          return;
        }
        if (chunkSize === 0) return controller.terminate();

        if (buffer.length < newLineIndex + 2 + chunkSize + 2) return;
        controller.enqueue(
          buffer.slice(newLineIndex + 2, newLineIndex + 2 + chunkSize)
        );
        buffer = buffer.slice(newLineIndex + 2 + chunkSize + 2);
      }
    },
  });
}

/** @param {Headers} headers */
function storeCookies(headers) {
  const cookies = headers.getSetCookie
    ? headers.getSetCookie()
    : [headers.get("Set-Cookie") ?? ""].filter(Boolean);

  cookies.forEach((cookie) => {
    const [nameValue, ...properties] = cookie.split("; ");

    // Not possible to store HttpOnly cookies securely
    if (properties.includes("HttpOnly") && !DANGEROUSLY_STORE_HTTPONLY_COOKIES)
      return;

    const [name, value] = nameValue.split("=");
    const cookieOptions = Object.fromEntries(
      properties.map((property) => {
        const [name, value] = property.split("=");
        if (name === "Max-Age")
          return [
            "expires",
            new Date(Date.now() + parseInt(value) * 1000).toUTCString(),
          ];
        return [
          lowerCaseFirstLetter(name),
          value === undefined ? decodeURIComponent(value) : true,
        ];
      })
    );
    cookieOptions.expires = cookieOptions.expires
      ? new Date(cookieOptions.expires).getTime()
      : null;
    cookieOptions.sameSite = lowerCaseFirstLetter(cookieOptions.sameSite);
    self.cookieStore.set({ ...cookieOptions, name, value });
  });
}

/** @param {ReadableStream<ArrayBuffer>} readable */
async function decodeHttpResponse(readable) {
  const reader = readable.getReader();

  const decoder = new TextDecoder();
  let headerChunks = "";
  let rest = new Uint8Array();
  while (true) {
    const { value, done } = await reader.read();
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
  const statusMatch = statusLine.match(/HTTP\/1.1 (\d+) (.+)/);
  if (!statusMatch)
    return new Response("Invalid HTTP Response", {
      status: 502,
      statusText: "Bad Gateway",
    });
  const [, status, statusText] = statusMatch;
  const headers = new Headers(
    Object.fromEntries(headerLines.map((line) => line.split(": ", 2)))
  );

  storeCookies(headers);

  const contentLength = headers.has("Content-Length")
    ? parseInt(headers.get("Content-Length"))
    : null;
  let lengthRead = rest.length;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(rest);
    },
    async pull(controller) {
      const { value, done } = await reader.read();
      if (done) return controller.close();
      controller.enqueue(value);
      lengthRead += value.length;
      if (lengthRead >= contentLength) controller.close();
    },
  });

  const responseBody =
    headers.get("Transfer-Encoding") === "chunked"
      ? body.pipeThrough(decodeChunkedTransformer())
      : lengthRead === contentLength
      ? rest
      : body;

  const response = new Response(responseBody, {
    status: parseInt(status),
    statusText,
    headers,
  });
  return response;
}

/**
 * @param {Request} request
 * @param {{ readable: ReadableStream<ArrayBuffer>, writable: WritableStream<ArrayBuffer> }} stream
 */
function fetchThroughStream(request, stream) {
  encodeHttpRequest(request).pipeTo(stream.writable);
  return decodeHttpResponse(stream.readable);
}

/**
 * @param {Request} request
 * @param {{
 *   url: string,
 *   serverCertificateHashes: string[],
 *   ctx: { waitUntil: (promise: Promise<void>) => void },
 * }} options
 * @returns {Promise<Response>}
 */
async function fetchThroughWebTransport(
  request,
  { url, serverCertificateHashes, ctx }
) {
  const cache = await caches.open("webtransportify");
  const cachedResponse = await cache.match(request);
  if (cachedResponse) return cachedResponse;

  const wt = new WebTransport(url, {
    serverCertificateHashes: serverCertificateHashes.map((hash) => ({
      algorithm: "sha-256",
      value: base64ToArrayBuffer(hash),
    })),
  });

  await timeoutWrapper(wt.ready, 10000, "WebTransport timeout");

  const stream = await wt.createBidirectionalStream();
  const response = await fetchThroughStream(request, stream);
  if (
    response.ok &&
    !response.headers.get("content-type")?.startsWith("text/html")
  )
    ctx.waitUntil(cache.put(request, response.clone()));
  return response;
}

/**
 * @param {Request} request
 * @param {{ waitUntil: (promise: Promise<void>) => void }} ctx
 */
async function fetchResponse(request, ctx) {
  const certObj = await certificateFetcher();

  const { url, certificate_hash, alt_certificate_hash } = certObj;
  const serverCertificateHashes = alt_certificate_hash
    ? [certificate_hash, alt_certificate_hash]
    : [certificate_hash];

  return timeoutWrapper(
    fetchThroughWebTransport(request, { url, serverCertificateHashes, ctx }),
    15000,
    "Request timeout"
  );
}

function renderErrorTemplate(message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: sans-serif; }
    h1 { font-size: 1.6em; }
  </style>
</head>
<body>
  <h1>Gateway Error</h1>
  <div>${message}</div>
</body>
</html>`;
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

  event.respondWith(
    fetchResponse(event.request, {
      waitUntil: (promise) => event.waitUntil(promise),
    }).catch(
      (e) =>
        new Response(renderErrorTemplate(e.message), {
          status: 502,
          headers: { "Content-Type": "text/html" },
        })
    )
  );
});
