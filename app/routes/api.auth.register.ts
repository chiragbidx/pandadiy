import { json, type ActionFunctionArgs } from '@remix-run/cloudflare';
import { z } from 'zod';
import { createUser, findUserByEmail } from '~/lib/.server/auth/db';
import { hashPassword } from '~/lib/.server/auth/password';
import { createSessionToken, serializeSessionCookie } from '~/lib/.server/auth/session';
import { sanitizeErrorMessage, withSecurity } from '~/lib/security';

const registerSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(8).max(128),
  name: z.string().trim().min(1).max(100).optional(),
});

async function registerAction({ request }: ActionFunctionArgs) {
  try {
    const body = await request.json();
    const parsed = registerSchema.safeParse(body);

    if (!parsed.success) {
      return json({ error: 'Invalid request body', details: parsed.error.flatten() }, { status: 400 });
    }

    const { email, password, name } = parsed.data;
    const existingUser = await findUserByEmail(email);

    if (existingUser) {
      return json({ error: 'Email is already registered' }, { status: 409 });
    }

    const passwordHash = await hashPassword(password);
    const user = await createUser(email, passwordHash, name);
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
        status: 201,
        headers: {
          'Set-Cookie': serializeSessionCookie(token),
        },
      },
    );
  } catch (error) {
    return json({ error: sanitizeErrorMessage(error, process.env.NODE_ENV === 'development') }, { status: 500 });
  }
}

export const action = withSecurity(registerAction, {
  allowedMethods: ['POST'],
});
