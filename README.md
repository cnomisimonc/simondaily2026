# Simon Daily Dashboard

Static site deployed via Cloudflare Pages. The live page is index.html (auto-generated).

## Access gate

`functions/_middleware.js` sits in front of every request. Visitors must enter an
allowed email address **and** the shared site password; a valid login sets a
signed, HttpOnly cookie that lasts 30 days. There are no emailed PIN codes and
no Cloudflare Access dependency.

Secrets are **never** stored in this repo. Set them in the Cloudflare dashboard:

> Workers & Pages → `simondaily2026` → Settings → Variables and secrets
> (add to **both** Production and Preview)

| Variable | Purpose |
| --- | --- |
| `SITE_PASSWORD` | The shared password everyone types. |
| `ALLOWED_EMAILS` | Comma-separated permitted addresses. A bare `@example.com` entry allows every address at that domain. |
| `AUTH_SECRET` | Long random string used to sign the session cookie. Changing it signs everyone out immediately. |

Until all three are set the site returns a "Setup required" page and stays
closed to everyone (it fails closed, not open).

### Day-to-day

- **Add or remove someone:** edit `ALLOWED_EMAILS`, then redeploy.
- **Change the password:** edit `SITE_PASSWORD`, then redeploy. Existing
  sessions stay valid until they expire — to force everyone out, also rotate
  `AUTH_SECRET`.
- **Sign out:** visit `/__auth/logout`.

Because one password is shared, the email list is a soft gate: it records who
claims to be signing in, but anyone holding the password could enter any
whitelisted address. Move to per-email passwords or an identity provider if you
need to distinguish viewers with confidence.

The daily rebuild task only touches `index.html`, so the gate survives each
automated publish.
