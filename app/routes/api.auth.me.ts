import { json, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { findUserById } from '~/lib/.server/auth/db';
import { getSessionTokenFromRequest, verifySessionToken } from '~/lib/.server/auth/session';
import { sanitizeErrorMessage, withSecurity } from '~/lib/security';

async function meLoader({ request }: LoaderFunctionArgs) {
  try {
    const token = getSessionTokenFromRequest(request);

    if (!token) {
      return json({ authenticated: false }, { status: 401 });
    }

    const payload = await verifySessionToken(token);

    if (!payload) {
      return json({ authenticated: false }, { status: 401 });
    }

    const user = await findUserById(payload.userId);

    if (!user) {
      return json({ authenticated: false }, { status: 401 });
    }

    return json({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    return json({ error: sanitizeErrorMessage(error, process.env.NODE_ENV === 'development') }, { status: 500 });
  }
}

export const loader = withSecurity(meLoader, {
  allowedMethods: ['GET'],
});
