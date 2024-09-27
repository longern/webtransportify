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

    if (!certificate) return new Response("Not Found", { status: 404 });
    const lastModified = new Date(certificate.last_modified).toUTCString();
    delete certificate.last_modified;

    return Response.json(certificate, {
      headers: { "Last-Modified": lastModified },
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
};

export const onRequestPost = async (context: any) => {
  const { request, env } = context;
  const db = env.DB;

  const { tunnel_id: tunnelId } = await request.json();
  if (!tunnelId) return new Response("Bad Request", { status: 400 });

  try {
    await db
      .prepare("INSERT INTO wt_hostnames (hostname, tunnel_id) VALUES (?, ?)")
      .bind(request.headers.get("Host"), tunnelId)
      .first();

    return new Response(null, { status: 204 });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
};
