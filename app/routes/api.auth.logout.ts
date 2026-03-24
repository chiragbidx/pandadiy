import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { clearSessionCookie } from '~/lib/.server/auth/session';
import { sanitizeErrorMessage, withSecurity } from '~/lib/security';

async function logoutAction(_args: ActionFunctionArgs) {
  try {
    return json(
      { ok: true },
      {
        headers: {
          'Set-Cookie': clearSessionCookie(),
        },
      },
    );
  } catch (error) {
    return json({ error: sanitizeErrorMessage(error, process.env.NODE_ENV === 'development') }, { status: 500 });
  }
}

export const action = withSecurity(logoutAction, {
  allowedMethods: ['POST'],
});

