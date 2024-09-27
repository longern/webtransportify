export const onRequestPost = async (context: {
  request: Request;
  env: any;
}) => {
  const { request, env } = context;
  const db = env.DB;

  await db.exec(
    `\
  CREATE TABLE IF NOT EXISTS wt_tunnels (\
    id TEXT PRIMARY KEY,\
    endpoint TEXT,\
    certificate_hash TEXT,\
    alt_certificate_hash TEXT,\
    token TEXT,\
    last_modified INTEGER\
  );
  CREATE TABLE IF NOT EXISTS wt_hostnames (\
    hostname TEXT PRIMARY KEY,\
    tunnel_id TEXT,\
    FOREIGN KEY (tunnel_id) REFERENCES wt_tunnels(id)\
  );`
  );

  const id = crypto.randomUUID();
  const endpoint = request.headers.get("X-WT-Endpoint");
  const certificateHash = await request.text();
  const token = crypto.randomUUID();
  const dateHeader = request.headers.get("Date");
  const now = dateHeader ? new Date(dateHeader).getTime() : Date.now();

  try {
    await db
      .prepare(
        `INSERT INTO wt_tunnels (id, endpoint, certificate_hash, alt_certificate_hash, token, last_modified) VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(id, endpoint, certificateHash, null, token, now)
      .run();
  } catch (e) {
    return new Response("Conflict", { status: 409 });
  }

  return Response.json({ id, token }, { status: 201 });
};
