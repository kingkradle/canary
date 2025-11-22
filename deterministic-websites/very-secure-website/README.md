Not so much a vulnerability, but this will report any "active scanning", i.e. when an attacker is looking for resources that may be exposed on a site that shouldn't be, or which might offer an entrypoint for an attack. It simply reports any request that goes to a route that isn't the homepage (`/`) of the app. This is more of a baseline of how many attacks are being attempted rather than checking a success rate.

To run, add the following to `.env.local`:

```
# Get from the supabase console
NEXT_PUBLIC_SUPABASE_URL=""
SUPABASE_SERVICE_KEY=""
```

Then:

```
pnpm dev
```
