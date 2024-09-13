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

  const certificateHash = await request.text();
  const now = request.headers.has("Date")
    ? new Date(request.headers.get("Date")).getTime()
    : Date.now();

  await db
    .prepare(
      "UPDATE wt_certificates SET certificate_hash = ?, alt_certificate_hash = certificate_hash, updated_at = ? WHERE domain = ?"
    )
    .bind(certificateHash, now, params.domain)
    .exec();

  return new Response(null, { status: 204 });
};
