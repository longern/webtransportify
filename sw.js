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

/**
 * @param {Request} request
 * @returns ReadableStream
 */
function encodeHttpRequest(request) {
  const url = new URL(request.url);
  const host = url.searchParams.get("wthost") || url.host;
  url.searchParams.delete("wturl");
  url.searchParams.delete("wtsch");
  url.searchParams.delete("wthost");
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

function timeoutWrapper(promise, timeout, message = "Timeout") {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(message));
    }, timeout);
    promise.then(resolve, reject).finally(() => clearTimeout(timer));
  });
}

/**
 * @param {ReadableStream} readable
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

  const contentLength = parseInt(headers.get("Content-Length"));
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

self.addEventListener("fetch", async (event) => {
  const request = event.request;
  const url = new URL(request.url);

  function detectUrlAndCertificate() {
    const url = new URL(request.url);
    const wturl = url.searchParams.get("wturl");
    const wtsch = (url.searchParams.get("wtsch") ?? "").split(",");
    if (wturl && wtsch.length) {
      return {
        url: wturl,
        serverCertificateHashes: wtsch,
      };
    }

    if (request.referrer) {
      const url = new URL(request.referrer);
      const wturl = url.searchParams.get("wturl");
      const wtsch = (url.searchParams.get("wtsch") ?? "").split(",");
      if (wturl && wtsch.length) {
        return {
          url: wturl,
          serverCertificateHashes: wtsch,
        };
      }
    }

    return { url: null, serverCertificateHashes: null };
  }

  const { url: webTransportUrl, serverCertificateHashes } =
    detectUrlAndCertificate();

  if (url.origin !== self.location.origin || !webTransportUrl) return;

  event.respondWith(
    (async () => {
      const wt = new WebTransport(`https://${webTransportUrl}`, {
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
        return response;
      } catch (e) {
        console.error(e);
        return fetch(request);
      }
    })()
  );
});
