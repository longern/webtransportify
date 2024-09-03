import { Http3Server } from "@fails-components/webtransport";
import { execSync } from "child_process";
import { X509Certificate, randomUUID } from "crypto";
import fs from "fs";
import net from "net";

const CREATE_CERTIFICATE_COMMAND = `\
openssl req -new \
-newkey ec \
-pkeyopt ec_paramgen_curve:prime256v1 \
-x509 \
-nodes \
-days 14 \
-out ./cert.pem \
-keyout ./key.pem \
-subj '/CN=Test Certificate' \
-addext 'subjectAltName = DNS:localhost'`;

function createCertificate() {
  execSync(CREATE_CERTIFICATE_COMMAND);

  const certFile = fs.readFileSync("./cert.pem");
  const privKey = fs.readFileSync("./key.pem");
  const cert = new X509Certificate(certFile);

  const hash = Buffer.from(
    cert.fingerprint256.split(":").map((el) => parseInt(el, 16))
  );

  return { cert: certFile, privKey, hash };
}

function reuseOrCreateCertificate() {
  try {
    const certFile = fs.readFileSync("./cert.pem");
    const privKey = fs.readFileSync("./key.pem");
    const cert = new X509Certificate(certFile);
    if (new Date(cert.validTo) < new Date()) throw new Error("Expired");

    const hash = Buffer.from(
      cert.fingerprint256.split(":").map((el) => parseInt(el, 16))
    );

    return { cert: certFile, privKey, hash };
  } catch (e) {
    return createCertificate();
  }
}

/**
 * @param {WebTransport} session
 * @param {{
 *   protocol: "tcp" | "udp"
 *   port: number
 * }} options
 */
async function readStreamLoop(
  session,
  { port, host = undefined, socketTimeout = 3000 }
) {
  const client = new net.Socket();

  try {
    await new Promise((resolve, reject) => {
      host
        ? client.connect(port, host, () => resolve(undefined))
        : client.connect(port, () => resolve(undefined));
      setTimeout(reject, socketTimeout);
    });
  } catch (e) {
    console.error("TCP connection error:", e);
    session.close();
  }

  session.closed.finally(() => client.destroySoon());
  client.on("end", () => session.close());

  try {
    /** @type {ReadableStreamDefaultReader<WebTransportBidirectionalStream>} */
    const streamReader = session.incomingBidirectionalStreams.getReader();
    const { value: stream, done } = await streamReader.read();
    if (done) return;
    const writer = stream.writable.getWriter();
    const writeChunk = (data) => writer.write(data);
    client.on("data", writeChunk);
    client.on("end", () => writer.close());
    session.closed.finally(() => client.off("data", writeChunk));

    for await (const chunk of stream.readable) client.write(chunk);
  } catch (e) {}
}

/**
 * @param {ReadableStream<WebTransport>} sessionStream
 * @param {Parameters<typeof readStreamLoop>[1]} options
 */
async function sessionStreamLoop(sessionStream, options) {
  for await (const session of sessionStream) {
    session.ready.then(() => readStreamLoop(session, options));
  }
}

/** @param {Buffer} hash */
function notifyCertUpdate(hash) {
  console.log("Cert hash:", hash.toString("base64"));
}

async function main() {
  const tcpPort = process.argv[2];

  if (!tcpPort) {
    console.log("Usage: node server.js <tcp-port>");
    process.exit(1);
  }

  const { cert, privKey, hash } = reuseOrCreateCertificate();
  const port = 34433;

  console.log();
  console.log("URL:", `127.0.0.1:${port}`);
  notifyCertUpdate(hash);

  const server = new Http3Server({
    port,
    host: "0.0.0.0",
    secret: randomUUID(),
    cert,
    privKey,
  });

  await server.createTransportInt();

  const sessionStream = server.sessionStream("/");

  sessionStreamLoop(sessionStream, { port: tcpPort });

  setInterval(() => {
    const { cert, privKey, hash } = createCertificate();
    notifyCertUpdate(hash);
    server.updateCert(cert, privKey);
  }, 1000 * 60 * 60 * 24 * 13);

  server.startServer();
}

main();
