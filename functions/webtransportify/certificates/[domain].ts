export const onRequestGet = async (context: any) => {
  const { env, params } = context;
  const db = env.DB;
  const domain = decodeURIComponent(params.domain);
  const certificate = await db
    .prepare("SELECT * FROM wt_certificates WHERE domain = ?")
    .bind(domain)
    .first();

  if (!certificate) return new Response("Not Found", { status: 404 });

  return Response.json(certificate, {
    headers: { "Content-Type": "application/json" },
  });
};

export const onRequestPost = async (context: any) => {
  const { request, env, params } = context;
  const db = env.DB;

  const domain = decodeURIComponent(params.domain);
  const certificateHash = await request.text();
  const now = request.headers.has("Date")
    ? new Date(request.headers.get("Date")).getTime()
    : Date.now();

  try {
    await db
      .prepare(
        "UPDATE wt_certificates SET certificate_hash = ?, alt_certificate_hash = certificate_hash, updated_at = ? WHERE domain = ?"
      )
      .bind(certificateHash, now, domain)
      .all();
  } catch (e) {
    return new Response("Not Found", { status: 404 });
  }

  return new Response(null, { status: 204 });
};

export const onRequestPut = async (context: any) => {
  const { request, env, params } = context;
  const db = env.DB;

  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS wt_certificates (
        domain TEXT PRIMARY KEY,
        url TEXT,
        certificate_hash TEXT,
        alt_certificate_hash TEXT,
        updated_at INTEGER
      )`
    )
    .run();

  const domain = decodeURIComponent(params.domain);
  const url = request.headers.get("X-WT-Certificate-URL");
  const certificateHash = await request.text();
  const now = request.headers.has("Date")
    ? new Date(request.headers.get("Date")).getTime()
    : Date.now();

  try {
    await db
      .prepare(
        `INSERT INTO wt_certificates (domain, url, certificate_hash, alt_certificate_hash, updated_at) VALUES (?, ?, ?, ?, ?)`
      )
      .bind(domain, url, certificateHash, null, now)
      .run();
  } catch (e) {
    return new Response("Conflict", { status: 409 });
  }

  return new Response(null, { status: 204 });
};
