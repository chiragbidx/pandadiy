import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { z } from 'zod';
import { findUserByEmail } from '~/lib/.server/auth/db';
import { verifyPassword } from '~/lib/.server/auth/password';
import { createSessionToken, serializeSessionCookie } from '~/lib/.server/auth/session';
import { sanitizeErrorMessage, withSecurity } from '~/lib/security';

const loginSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(1).max(128),
});

async function loginAction({ request }: ActionFunctionArgs) {
  try {
    const body = await request.json();
    const parsed = loginSchema.safeParse(body);

    if (!parsed.success) {
      return json({ error: 'Invalid request body', details: parsed.error.flatten() }, { status: 400 });
    }

    const { email, password } = parsed.data;
    const user = await findUserByEmail(email);

    if (!user) {
      return json({ error: 'Invalid email or password' }, { status: 401 });
    }

    const isValidPassword = await verifyPassword(password, user.password_hash);

    if (!isValidPassword) {
      return json({ error: 'Invalid email or password' }, { status: 401 });
    }

    const token = await createSessionToken({ userId: user.id, email: user.email });

    return json(
      {
        ok: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      },
      {
        headers: {
          'Set-Cookie': serializeSessionCookie(token),
        },
      },
    );
  } catch (error) {
    return json({ error: sanitizeErrorMessage(error, process.env.NODE_ENV === 'development') }, { status: 500 });
  }
}

export const action = withSecurity(loginAction, {
  allowedMethods: ['POST'],
});
