export const onRequestPut = async (context: any) => {
  const { request, env } = context;
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
    .exec();

  return new Response(null, { status: 204 });
};
