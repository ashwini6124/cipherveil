# CipherVeil

CipherVeil is a Streamlit steganography application. User accounts and activity
history are backed by Supabase; steganography payloads and encryption passwords
are not written to the activity log.

## Supabase setup

1. Create a Supabase project and copy its project URL, anon/public key, and
   service-role key from **Project Settings → API**.
2. In the Supabase SQL Editor, run [`supabase/schema.sql`](./supabase/schema.sql).
   The activity table has row-level security enabled and grants data access only
   to the server-side `service_role` key.
3. Enable email/password sign-up in **Authentication → Providers → Email**.
   Configure email confirmation and SMTP before opening signup to the public.
   After deployment, set the Supabase **Authentication → URL Configuration → Site
   URL** to the Streamlit app URL so email-confirmation links return to the app.
4. Set the secrets below in Streamlit Community Cloud's app settings. For local
   development, the same names can be placed in the ignored `.env` file.

```toml
SUPABASE_URL = "https://YOUR_PROJECT.supabase.co"
SUPABASE_ANON_KEY = "your-supabase-anon-key"
SUPABASE_SERVICE_ROLE_KEY = "your-supabase-service-role-key"
TEAM_AUDIT_PASSWORD = "choose-a-random-passphrase-at-least-16-characters"
TEAM_AUDIT_EMAILS = [
  "first-team-member@example.com",
  "second-team-member@example.com",
  "third-team-member@example.com",
  "fourth-team-member@example.com",
]

# Optional:
GEMINI_API_KEY = "your-gemini-api-key"
GEMINI_MODEL = "gemini-3.6-flash"
```

Keep the service-role key and audit passphrase private. Never commit `.env` or
paste the service-role key into application code. Only the four addresses in
`TEAM_AUDIT_EMAILS` can unlock the team-wide activity page, and they must also
enter a `TEAM_AUDIT_PASSWORD` of at least 16 characters. Each person should
first register and confirm their email through the app.

For local `.env` files, put one setting per line and use a comma-separated
string for the team emails, for example:

```dotenv
TEAM_AUDIT_EMAILS=first@example.com,second@example.com,third@example.com,fourth@example.com
```

The activity log records sign-ups, sign-ins, and completed conceal/extract
operations, including carrier and cipher metadata. It does not store hidden
messages, uploaded file contents, encryption/decryption passwords, or message
hashes. Users can see their own activity; the allowlisted team accounts can
review the shared history after unlocking the audit page.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud

1. Push this repository to GitHub without `.env`, generated archives, or virtual
   environments.
2. Create a new app at <https://share.streamlit.io>, select this repository,
   branch, and `app.py`.
3. Add the Supabase settings above under the app's **Settings → Secrets**.
4. Deploy, then test account confirmation, sign-in, operation logging, and the
   team audit screen using one allowlisted team address.

Deployment cannot be completed from this checkout alone: it requires your
GitHub/Streamlit Cloud account and a configured Supabase project. Do not share
the service-role key or audit passphrase in chat.
