import { Container, getContainer } from '@cloudflare/containers';
import { env } from 'cloudflare:workers';

export class RustContainer extends Container<Env> {
  // Port the container listens on (default: 8080)
  defaultPort = 8080;

  // Time before container sleeps due to inactivity (default: 30s)
  sleepAfter = '30s';

  // Environment variables passed to the container
  envVars = {
    HELLO: env.HELLO,
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
  async fetch(request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // 1. Backend Routing
    if (url.pathname.startsWith('/api/')) {
      const container = getContainer(env.RUST_CONTAINER);
      return await container.fetch(request);
    }

    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
