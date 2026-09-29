import { Container, getContainer } from '@cloudflare/containers';
import { env } from 'cloudflare:workers';
import queries from './queries/index.ts';

export class RustContainer extends Container<Env> {
  // Port the container listens on (default: 8080)
  defaultPort = 8080;

  // Time before container sleeps due to inactivity (default: 30s)
  sleepAfter = '30s';

  // Environment variables passed to the container
  envVars = {
    ORIGIN: env.ORIGIN,
  };

  static outboundByHost = {
    'd1.webgl3d.dev': async function (
      request: Request,
      env: Env,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _ctx: ExecutionContext,
    ) {
      const url = new URL(request.url);
      switch (url.pathname) {
        case '/query': {
          const query = queries[url.searchParams.get('name') || ''];
          if (query) {
            const preparedQuery = env.DB.prepare(query);
            url.searchParams.forEach((value, key) => {
              if (key === 'arg') {
                preparedQuery.bind(value);
              }
            });

            const [result] = await env.DB.batch([preparedQuery]);
            console.log(result);
          } else {
            return new Response('{}', {
              status: 400,
              headers: { 'Content-Type': 'application/json' },
            });
          }
        }
      }

      console.error(`Unidentified internal request: ${url.pathname}`);
      return new Response('{}', {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    },
  };

  // Optional lifecycle hooks
  override onStart() {
    console.log('Container successfully started');
  }

  override onStop() {
    console.log('Container successfully shut down');
  }

  override onError(error: unknown) {
    console.log('Container error:', error);
  }
}

export default {
  /**
   * This is the standard fetch handler for a Cloudflare Worker
   *
   * @param request - The request submitted to the Worker from the client
   * @param env - The interface to reference bindings declared in wrangler.jsonc
   * @param _ctx - The execution context of the Worker
   * @returns The response to be sent back to the client
   */
  async fetch(
    request: Request,
    env: Env,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    // 1. Backend Routing
    if (url.pathname.startsWith('/api/')) {
      const container = getContainer(env.RUST_CONTAINER);
      return await container.fetch(request);
    }

    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
