import { Container, getContainer } from '@cloudflare/containers';
import { env } from 'cloudflare:workers';
import { query } from './controllers/sql.ts';
export { ContainerProxy } from '@cloudflare/containers';

export class RustContainer extends Container<Env> {
  // Port the container listens on (default: 8080)
  defaultPort = 8080;

  // Our container doesn't need to reach the outside world.
  enableInternet = false;

  // Time before container sleeps due to inactivity (default: 30s)
  sleepAfter = '30s';

  // Environment variables passed to the container
  envVars = {
    ORIGIN: env.ORIGIN,
    JWT__PRIVATE_KEY: env.JWT__PRIVATE_KEY,
    JWT__PUBLIC_KEY: env.JWT__PUBLIC_KEY,
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

RustContainer.outboundByHost = {
  'd1.webgl3d.dev': async function (
    request: Request,
    env: Env,
  ): Promise<Response> {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/query':
        return await query(url, env);
      default:
        console.error(`Unidentified internal request: ${url.pathname}`);
        return new Response('{}', {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
    }
  },
};

export default {
  /**
   * This is the standard fetch handler for a Cloudflare Worker
   *
   * @param request - The request submitted to the Worker from the client
   * @param env - The interface to reference bindings declared in wrangler.jsonc
   * @param ctx - The execution context of the Worker
   * @returns The response to be sent back to the client
   */
  async fetch(
    request: Request,
    env: Env,
    //ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    // 1. Backend Routing
    if (
      url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/.well-known/')
    ) {
      const container = getContainer(env.RUST_CONTAINER);
      return await container.fetch(request);
    }

    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
