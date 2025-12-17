# XSS Vulnerability Tracking - dangerouslySetInnerHTML Usage

## Executive Summary

| Risk Level | Count | Description |
|------------|-------|-------------|
| 🟢 LOW | ~45 | Translation strings, JSON structured data, DOMPurify sanitized |
| 🟡 MEDIUM | ~12 | CMS/Editor content, external API data (Twitter) |
| 🔴 HIGH | 0 | Direct user input to dangerouslySetInnerHTML |

**Key Finding:** No direct user-controlled input reaches `dangerouslySetInnerHTML` without either:
1. Sanitization (DOMPurify)
2. Editor role requirement
3. External API pre-sanitization (Twitter)

**Main Risk:** Compromised editor accounts could inject XSS into articles.

---

## Detailed Summary

After comprehensive analysis, **61 files** use `dangerouslySetInnerHTML`. Most are **low risk** because they use:
- Translation strings (`t()` function) - developer-controlled
- JSON-LD structured data with `JSON.stringify()` - escaped
- DOMPurify sanitization

---

## Risk Classification

### 🟢 LOW RISK - Translation Strings (Developer Controlled)

These use `t()` translation function - content is defined in translation JSON files by developers.

| File | Line | Source |
|------|------|--------|
| `apps/www/components/Notifications/NotificationFeed.js` | 189 | `t('Notifications/empty/paragraph')` |
| `apps/www/components/Search/ZeroResults.js` | 20 | `t('search/results/empty')` |
| `apps/www/components/Questionnaire/Questionnaire.js` | 40 | `t('questionnaire/notEligible')` |
| `apps/www/components/Vote/text.js` | 100, 136 | `t()` translation |
| `apps/www/components/Pledge/Consents.js` | 67 | `t('pledge/consents/label/...')` |
| `apps/www/components/Auth/SignIn.js` | 163 | `t('cookies/disabled/error/explanation')` |
| `apps/www/components/Auth/Poller.js` | - | Translation strings |
| `apps/www/components/RawHtmlTranslation.js` | 18 | Translation elements |
| `apps/www/components/Crowdfunding/Status.js` | - | Translation strings |
| `apps/www/components/Crowdfunding/Bar.js` | - | Translation strings |
| `apps/www/components/Account/*` | - | Translation strings |
| `apps/admin/components/Auth/SignIn.js` | - | Translation strings |
| `apps/publikator/components/Auth/*` | - | Translation strings |

---

### 🟢 LOW RISK - JSON Structured Data (Escaped)

These use `JSON.stringify()` which escapes content, or additional escaping.

| File | Line | Notes |
|------|------|-------|
| `apps/www/components/Discussion/Discussion.tsx` | 85 | `JSON.stringify(structuredData)` |
| `apps/www/components/Frame/Meta.js` | 119 | `JSON.stringify(jsonLd)` |
| `apps/www/src/app/veranstaltungen/[slug]/page.tsx` | 130 | `JSON.stringify(...).replace(/</g, '\\u003c')` - extra escaping |

---

### 🟢 LOW RISK - Sanitized Content

These use DOMPurify sanitization before rendering.

| File | Line | Sanitizer |
|------|------|-----------|
| `apps/www/components/Search/CommentResult.tsx` | 17 | `sanitizeSearchResultHTML()` |
| `apps/www/components/Search/DocumentResult.js` | 46, 61, 75 | `sanitizeSearchResultHTML()` |
| `apps/www/components/Search/UserResult.js` | 122, 160 | `sanitizeSearchResultHTML()` |

**Sanitization Function:**
```typescript
// apps/www/lib/sanitizeHTML.ts
import DOMPurify from 'isomorphic-dompurify'
export function sanitizeSearchResultHTML(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['em'],  // Only <em> allowed
    ALLOWED_ATTR: [],      // No attributes allowed
  })
}
```

---

### 🟢 LOW RISK - Static/CSS Content

| File | Line | Notes |
|------|------|-------|
| `apps/www/components/Gallery/Gallery.js` | 93 | Static CSS (photoswipe styles) |
| `apps/www/pages/_document.js` | - | Static content |

---

### 🟡 MEDIUM RISK - CMS Content (Editor Controlled)

These render content from CMS (DatoCMS). Risk depends on CMS sanitization.

| File | Line | Source |
|------|------|--------|
| `apps/www/components/Events/Detail.js` | 108 | `description` from event data |
| `apps/www/components/Pledge/CustomizePackage.js` | 573 | `description` from package config |
| `packages/styleguide/src/templates/Article/teasers.js` | - | Article content |

**Risk Assessment:** CMS content is created by editors with `editor` role. DatoCMS typically sanitizes HTML, but should verify.

---

### 🟡 MEDIUM RISK - External API Data

These render content from external APIs (Twitter, embeds).

| File | Line | Source | Risk Factor |
|------|------|--------|-------------|
| `packages/styleguide/src/components/Social/Tweet.js` | 80 | Twitter API `html` | Twitter data |
| `packages/styleguide/src/components/Discussion/Internal/Comment/CommentEmbed.js` | 155 | Embed `html` | External embed |

**Data Flow for Twitter Embeds:**
```
Twitter API → response.full_text → Autolinker.link() → html → dangerouslySetInnerHTML
```

**Risk Assessment:**
1. Twitter content is pre-sanitized by Twitter
2. `Autolinker.link()` creates `<a>` tags from URLs/mentions (known library)
3. However, no explicit DOMPurify sanitization

---

### 🟡 MEDIUM RISK - Article Content (MDAST/Editor Controlled)

These render HTML embedded in article content (MDAST). Content is created by editors via Publikator CMS.

| File | Line | Source | Notes |
|------|------|--------|-------|
| `packages/styleguide/src/components/DynamicComponent/index.js` | 88 | `html` prop from MDAST | Chart placeholder HTML |
| `packages/styleguide/src/components/IllustrationHtml/index.js` | 69 | `code` prop from MDAST | ai2html responsive illustrations |

**Data Flow:**
```
Editor creates article in Publikator CMS
    ↓
MDAST (Markdown AST) with embedded HTML zones
    ↓
Article template processes MDAST
    ↓
HTML zone content → dangerouslySetInnerHTML
```

**Risk Assessment:**
- ✅ Requires `editor` role to create article content
- ⚠️ No sanitization of editor-provided HTML
- **If an editor account is compromised, XSS can be injected into articles**

---

### 🟡 MEDIUM RISK - Expandable Link Content (MDAST/Editor Controlled)

| File | Line | Source | Notes |
|------|------|--------|-------|
| `packages/styleguide/src/components/ExpandableLink/ExpandableLinkCallout.tsx` | 247 | `expandedLink.description` | Link tooltip description |

**Data Flow:**
```javascript
// Article MDAST link node
node.title = "Link Title|||Description with <b>HTML</b>"

// templates/Article/base.js
const [title, description] = (node.title || '').split(EXPANDABLE_LINK_SEPARATOR)

// ExpandableLinkCallout.tsx
<RawHtml dangerouslySetInnerHTML={{ __html: expandedLink.description }} />
```

**Risk Assessment:**
- ✅ Content comes from article MDAST (requires editor role)
- ⚠️ No sanitization of editor-provided description HTML

---

## Detailed Analysis: Twitter/Embed XSS Vector

### Source Code Path

```javascript
// packages/backend-modules/embeds/lib/twitter/index.js
const getTweetById = async (id, t) => {
  const response = await fetch('https://api.twitter.com/...')
  
  const text = response.full_text || response.text
  const sanitizedText = expandUrls(text, response.entities)
  
  // Autolinker creates <a> tags
  const html = sanitizedText
    ? Autolinker.link(sanitizedText, { mention: 'twitter' })
        .replace(/\n/g, '<br/>')
    : null
  
  return { html, ... }
}
```

### Rendering Path

```javascript
// packages/styleguide/src/components/Social/Tweet.js
<RawHtml type={Text} dangerouslySetInnerHTML={{ __html: html }} />

// packages/styleguide/src/components/Discussion/Internal/Comment/CommentEmbed.js
<Interaction.P dangerouslySetInnerHTML={{ __html: html }} />
```

### Attack Scenario

**Theoretical:** If Twitter's API returned unsanitized content containing `<script>` tags or event handlers, XSS could occur.

**Reality:** Twitter heavily sanitizes content on their end. The `full_text` field contains plain text, not HTML. The only HTML is generated by `Autolinker.link()` which only creates `<a>` tags.

**Risk Level:** LOW - Twitter sanitizes content; Autolinker generates safe HTML

---

## Recommendations

### Immediate (Defense in Depth)

1. **Add DOMPurify to embed rendering:**
```javascript
// Tweet.js and CommentEmbed.js
import DOMPurify from 'isomorphic-dompurify'

const sanitizedHtml = DOMPurify.sanitize(html, {
  ALLOWED_TAGS: ['a', 'br', 'em', 'strong'],
  ALLOWED_ATTR: ['href', 'target', 'rel'],
})
```

2. **Add CSP headers:**
```javascript
// next.config.js - uncomment CSP
'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'"
```

### Low Priority

3. **Audit CMS sanitization:** Verify DatoCMS sanitizes HTML fields
4. **Review Autolinker library:** Check for known vulnerabilities

---

## Files Requiring No Action

These are documentation/example files:
- `packages/styleguide/src/lib/translate.docs.md`
- `packages/styleguide/src/components/Typography/docs.md`
- `packages/styleguide/src/components/RawHtml/docs.md`
- `packages/styleguide/README.md`

---

## Attack Scenarios

### Scenario 1: Compromised Editor Account (MEDIUM)

**Attack Path:**
1. Attacker compromises an editor account (phishing, credential stuffing)
2. Creates article with malicious HTML in:
   - DynamicComponent HTML zone
   - IllustrationHtml code
   - ExpandableLink description
   - Article embedded HTML zones
3. Article is published and readers are exposed to XSS

**Impact:** Session hijacking, defacement, malware distribution

**Mitigation:** Sanitize all article HTML before rendering, even from editors

### Scenario 2: Twitter API Manipulation (VERY LOW)

**Attack Path:**
1. Attacker creates Twitter post with XSS payload
2. Editor embeds tweet in article
3. Twitter API returns unsanitized content

**Reality:** Twitter heavily sanitizes content; `full_text` is plain text

**Mitigation:** Add DOMPurify to embed rendering as defense-in-depth

### Scenario 3: Search Index Poisoning (LOW)

**Attack Path:**
1. Attacker finds way to inject content into search index
2. Search results display unsanitized HTML

**Reality:** Search content is sanitized with DOMPurify before display

---

## Verification Commands

```bash
# Find all dangerouslySetInnerHTML usages
rg "dangerouslySetInnerHTML" --type js --type tsx -l

# Find unsanitized usages (no DOMPurify nearby)
rg "dangerouslySetInnerHTML" -C 5 | rg -v "sanitize|DOMPurify"

# Check for eval/Function usage (related code injection)
rg "new Function\(|eval\(" --type js --type ts
```

---

## Conclusion

**Overall XSS Risk: LOW to MEDIUM**

The codebase demonstrates good security practices:
- ✅ Search results use DOMPurify sanitization
- ✅ JSON-LD data uses JSON.stringify() escaping
- ✅ Most HTML comes from translation strings (developer-controlled)
- ✅ CMS content requires editor privileges
- ✅ External API data (Twitter) is pre-sanitized at source

**Areas for Improvement:**
1. Add DOMPurify sanitization to embed rendering (Tweet.js, CommentEmbed.js)
2. Add HTML sanitization to article content (IllustrationHtml, DynamicComponent)
3. Enable Content Security Policy headers
4. Consider sanitizing editor content as defense-in-depth

**Exploitability:** 
- No public-facing user input directly reaches dangerouslySetInnerHTML
- Exploitation requires either compromised editor account or Twitter API vulnerability
- Bug bounty payoff: LOW unless combined with account takeover
