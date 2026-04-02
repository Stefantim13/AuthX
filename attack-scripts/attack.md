# Ghid pentru rularea scripturilor de atac

Scripturile din acest folder sunt facute pentru branch-ul `vulnerable` si arata principalele probleme de securitate din aplicatie.

## Cum se ruleaza?

1. Treci pe branch-ul vulnerabil:

```bash
git switch vulnerable
```

2. Pornesti aplicatia:

```bash
npm start
```

3. Rulezi scriptul dorit:

```bash
node attack-scripts/brute-force-login.js
node attack-scripts/cookie-theft-demo.js
node attack-scripts/session-hijack-demo.js
node attack-scripts/reset-token-exploit.js
```

## Ce arata pe scurt?

- `brute-force-login.js` arata ca se pot incerca multe parole pana cand una functioneaza
- `cookie-theft-demo.js` arata cum poate fi obtinut cookie-ul de sesiune
- `session-hijack-demo.js` arata ca o sesiune furata poate fi refolosita
- `reset-token-exploit.js` arata ca resetarea parolei se poate abuza usor in varianta vulnerabila

Ideea este sa se vada diferenta dintre `vulnerable` si `secure`, adica intre o implementare usor de atacat si una in care aceste probleme au fost remediate.
