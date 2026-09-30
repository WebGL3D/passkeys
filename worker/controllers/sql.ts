import QUERIES from '../queries.ts';

export async function query(
  url: URL,
  env: Env,
): Promise<Response> {
  const name = url.searchParams.get('name') || '';
  const query = QUERIES[name];
  if (!query) {
    console.error('Attempted to run query that does not exist:', name);
    return new Response('{}', {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  // Fetch query parameters
  const queryParameters: string[] = [];
  url.searchParams.forEach((value, key) => {
    if (key === 'arg') {
      queryParameters.push(value);
    }
  });

  // Execute query
  const result = await env.DB.prepare(query)
    .bind(...queryParameters)
    .all();

  if (!result.success) {
    console.error('Failed to execute database query:', result);
    return new Response('{}', {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify(result.results), {
    headers: { 'Content-Type': 'application/json' },
  });
}
