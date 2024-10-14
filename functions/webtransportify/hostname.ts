export const onRequestGet = async (context: any) => {
  const { request, env } = context;
  const db = env.DB;
  try {
    const certificate = await db
      .prepare(
        `
SELECT endpoint, certificate_hash, alt_certificate_hash, last_modified
FROM wt_hostnames JOIN wt_tunnels
ON wt_hostnames.tunnel_id = wt_tunnels.id
WHERE hostname = ?
`
      )
      .bind(request.headers.get("Host"))
      .first();

    if (!certificate) {
      const { results: tunnels } = await db
        .prepare("SELECT id, endpoint FROM wt_tunnels")
        .all();
      return Response.json({ error: "Not Found", tunnels }, { status: 404 });
    }

    const lastModified = new Date(certificate.last_modified).toUTCString();
    delete certificate.last_modified;

    return Response.json(certificate, {
      headers: { "Last-Modified": lastModified },
    });
  } catch (e) {
    if (e.message.includes("no such table")) {
      return Response.json(
        { error: "Table not found", tunnels: [] },
        { status: 404 }
      );
    }
    return Response.json({ error: e.message }, { status: 500 });
  }
};

function initializeDatabase(db: any) {
  return db.exec(
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
}

export const onRequestPut = async (context: any) => {
  const { request, env } = context;
  const db = env.DB;

  let { tunnel_id: tunnelId } = await request.json();
  let token: string | undefined = undefined;

  const host = request.headers.get("Host");
  const hostExists = await db
    .prepare("SELECT hostname FROM wt_hostnames WHERE hostname = ?")
    .bind(host)
    .first();

  if (hostExists) {
    return new Response("Conflict", { status: 409 });
  }

  if (!tunnelId) {
    await initializeDatabase(db);

    const id = crypto.randomUUID();
    token = crypto.randomUUID().replace(/-/g, "");
    const dateHeader = request.headers.get("Date");
    const now = dateHeader ? new Date(dateHeader).getTime() : Date.now();

    try {
      await db
        .prepare(
          `INSERT INTO wt_tunnels (id, endpoint, certificate_hash, alt_certificate_hash, token, last_modified) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(id, null, null, null, token, now)
        .run();
    } catch (e) {
      return new Response("Conflict", { status: 409 });
    }

    tunnelId = id;
  }

  try {
    await db
      .prepare("INSERT INTO wt_hostnames (hostname, tunnel_id) VALUES (?, ?)")
      .bind(host, tunnelId)
      .run();

    return Response.json({ tunnel_id: tunnelId, token }, { status: 201 });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
};
