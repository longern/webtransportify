export const onRequestPost = async (context: any) => {
  const { request, env, params } = context;
  const db = env.DB;

  const id = params.id;
  const token = params.token;

  const tunnel = await db
    .prepare("SELECT id, token FROM wt_tunnels WHERE id = ?")
    .bind(id)
    .first();
  if (!tunnel) return new Response("Not Found", { status: 404 });
  if (tunnel.token !== token)
    return new Response("Unauthorized", { status: 401 });

  const { endpoint, certificate_hash: certificateHash } = await request.json();
  const now = request.headers.has("Date")
    ? new Date(request.headers.get("Date")).getTime()
    : Date.now();

  try {
    if (endpoint) {
      await db
        .prepare("UPDATE wt_tunnels SET endpoint = ? WHERE id = ?")
        .bind(endpoint, id)
        .all();
    }

    if (certificateHash) {
      await db
        .prepare(
          "UPDATE wt_tunnels SET certificate_hash = ?, alt_certificate_hash = certificate_hash, last_modified = ? WHERE id = ?"
        )
        .bind(certificateHash, now, id)
        .all();
    }
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }

  return new Response(null, { status: 204 });
};
