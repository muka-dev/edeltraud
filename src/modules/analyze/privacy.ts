import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, ModuleContext, ModuleResult, RenderData } from '../../core/types.ts';
import type { PageData } from '../util.ts';
import { classifyHost, isEuEeaCh, isUnknown, type ThirdPartyService } from './thirdparty-db.ts';

// ---------- shared helpers ----------

function getRender(ctx: ModuleContext): RenderData | undefined {
  return ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
}
function getPage(ctx: ModuleContext): PageData | undefined {
  return ctx.artifacts.list('page')[0]?.data as PageData | undefined;
}
/** Static resource URLs of the pages collect.crawl loaded (not rendered). */
function subpageUrls(ctx: ModuleContext): string[] {
  return ctx.artifacts.list('subpage').flatMap((a) => staticUrls((a.data as PageData).html, (a.data as PageData).finalUrl));
}

/** True if the body has (almost) no content: a JS app shell that needs rendering to show anything. */
export function isSpaShell(html: string): boolean {
  const body = html.match(/<body\b[^>]*>([\s\S]*)<\/body>/i)?.[1] ?? html;
  const stripped = body
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi, '');
  const text = stripped.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  const content = (stripped.match(/<(p|h[1-6]|a|img|li|button|form|input|article|section|main|nav|header|footer|table)\b/gi) ?? []).length;
  return text.length < 40 && content < 3;
}

const SKIP_REL = /\b(canonical|alternate|author|me|license|help|next|prev|search|manifest)\b/i;

/** URLs referenced by tags that load something (not plain anchors), plus url()/@import in <style>. */
export function staticUrls(html: string, base: string): string[] {
  const out = new Set<string>();
  const add = (ref: string | undefined) => {
    if (!ref) return;
    try {
      const u = new URL(ref.trim(), base);
      if (u.protocol === 'http:' || u.protocol === 'https:') out.add(u.toString());
    } catch {
      /* ignore */
    }
  };
  for (const m of html.matchAll(/<(script|link|img|iframe|source|video|audio|embed)\b([^>]*)>/gi)) {
    const tag = m[1]!.toLowerCase();
    const attrs = m[2] ?? '';
    if (tag === 'link' && SKIP_REL.test(attrs.match(/\brel\s*=\s*["']?([^"'>]*)/i)?.[1] ?? '')) continue;
    add(attrs.match(/\b(?:src|href)\s*=\s*["']?([^"'\s>]+)/i)?.[1]);
  }
  for (const m of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
    for (const r of (m[1] ?? '').matchAll(/(?:@import\s+(?:url\()?|url\()\s*["']?((?:https?:)?\/\/[^"')\s]+)/gi)) add(r[1]);
  }
  return [...out];
}

function pageHostOf(ctx: ModuleContext, page?: PageData, render?: RenderData): string {
  const u = render?.finalUrl ?? page?.finalUrl;
  try {
    return u ? new URL(u).hostname : ctx.target.host;
  } catch {
    return ctx.target.host;
  }
}

const label = (s: ThirdPartyService) => `${s.name} (${s.country})`;

function joinList(items: string[], max = 15): string {
  return items.slice(0, max).join(', ') + (items.length > max ? `, +${items.length - max}` : '');
}

// ---------- privacy.third-party ----------

/** Lists third-party hosts the page loads (render requests, else static HTML) and notes services outside the EU/EEA/CH. */
export const privacyThirdParty: CheckModule = {
  manifest: {
    id: 'privacy.third-party',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'privacy',
    requires: [],
    uses: ['artifact:render', 'artifact:page', 'artifact:subpage'],
    provides: ['fact:privacy.thirdParties'],
    params: {},
    budget: {},
  },
  run(ctx): ModuleResult {
    const m = privacyThirdParty.manifest;
    const render = getRender(ctx);
    const page = getPage(ctx);
    if (!render && !page) return {};
    if (!render && page && isSpaShell(page.html)) {
      return { notChecked: [{ module: m.id, reason: 'unsupported', detail: 'needs rendering' }] };
    }
    const pageHost = pageHostOf(ctx, page, render);
    const urls = [...(render ? render.requests.map((r) => r.url) : staticUrls(page!.html, page!.finalUrl)), ...subpageUrls(ctx)];
    const seen = new Map<string, ThirdPartyService | string>();
    for (const url of urls) {
      const c = classifyHost(url, pageHost);
      if (!c) continue;
      if (isUnknown(c)) {
        if (!seen.has('host:' + c.host)) seen.set('host:' + c.host, c.host);
      } else if (!seen.has(c.id)) seen.set(c.id, c);
    }
    const known = [...seen.values()].filter((v): v is ThirdPartyService => typeof v !== 'string');
    const facts = {
      'privacy.thirdParties': known.map((s) => ({ name: s.name, company: s.company, country: s.country, category: s.category })),
    };
    if (!seen.size) return { facts };
    const loc = { url: render?.finalUrl ?? page!.finalUrl };
    const confidence = render ? 'confirmed' : 'likely';
    const labels = [...seen.values()].map((v) => (typeof v === 'string' ? `${v} (unbekannt)` : label(v)));
    const findings: Finding[] = [
      finding(m, {
        kind: 'third-party',
        severity: 'info',
        confidence,
        location: loc,
        messageKey: 'privacy.third-party',
        vars: { count: String(seen.size), list: joinList(labels) },
      }),
    ];
    const outside = known.filter((s) => !isEuEeaCh(s.country));
    if (outside.length) {
      findings.push(
        finding(m, {
          kind: 'third-country',
          severity: 'low',
          confidence,
          location: loc,
          messageKey: 'privacy.third-country',
          vars: { list: joinList(outside.map(label)) },
        }),
      );
    }
    return { findings, facts };
  },
};

// ---------- privacy.google-fonts ----------

const FONT_HOST = /(^|\.)fonts\.(googleapis|gstatic)\.com$/i;

/** Google Fonts loaded from Google's servers (requests, or links/@import in the static HTML). */
export const privacyGoogleFonts: CheckModule = {
  manifest: {
    id: 'privacy.google-fonts',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'privacy',
    requires: [],
    uses: ['artifact:render', 'artifact:page', 'artifact:subpage'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx): ModuleResult {
    const m = privacyGoogleFonts.manifest;
    const render = getRender(ctx);
    const page = getPage(ctx);
    if (!render && !page) return {};
    const urls: string[] = [];
    if (render) urls.push(...render.requests.map((r) => r.url));
    if (page) urls.push(...staticUrls(page.html, page.finalUrl));
    urls.push(...subpageUrls(ctx));
    const hosts = new Set<string>();
    for (const u of urls) {
      try {
        const h = new URL(u).hostname.toLowerCase();
        if (FONT_HOST.test(h)) hosts.add(h);
      } catch {
        /* ignore */
      }
    }
    if (!hosts.size) {
      if (!render && page && isSpaShell(page.html)) {
        return { notChecked: [{ module: m.id, reason: 'unsupported', detail: 'needs rendering' }] };
      }
      return {};
    }
    return {
      findings: [
        finding(m, {
          kind: 'google-fonts',
          severity: 'low',
          confidence: 'confirmed',
          location: { url: render?.finalUrl ?? page!.finalUrl },
          messageKey: 'privacy.google-fonts',
          vars: { host: [...hosts].sort().join(', ') },
        }),
      ],
    };
  },
};

// ---------- privacy.consent-before-tracking ----------

const TRACKING_COOKIE =
  /^(_ga(_.+)?|_gid|_gat.*|_gcl_.+|_fbp|_fbc|_hjSession.*|_clck|_clsk|MUID|ajs_.+|mp_.+_mixpanel|_tt_.+|_ttp|li_.+|bcookie|IDE|test_cookie|_pin_unauth|ph_.+_posthog)$/;

const CMP_PATTERNS: { name: string; html: RegExp; cookie?: RegExp }[] = [
  { name: 'Cookiebot', html: /cookiebot\.com|CookieConsent\.|id=["']Cookiebot["']/i, cookie: /^CookieConsent$/ },
  { name: 'Usercentrics', html: /usercentrics\.(eu|com)|uc-central-/i, cookie: /^uc_/ },
  { name: 'OneTrust', html: /cookielaw\.org|onetrust\.com|OptanonConsent|ot-sdk-/i, cookie: /^OptanonConsent$/ },
  { name: 'Borlabs', html: /borlabs-cookie|BorlabsCookie/i, cookie: /^borlabs-cookie/ },
  { name: 'Klaro', html: /kiprotect\.com|klaro(\.js|-config|\.min\.js)|\bklaro\b/i, cookie: /^klaro$/ },
  { name: 'CookieYes', html: /cookieyes\.com|cky-consent/i, cookie: /^cookieyes-consent$/ },
  { name: 'Complianz', html: /complianz|cmplz/i, cookie: /^cmplz_/ },
  { name: 'Didomi', html: /didomi\.io|didomi-/i, cookie: /^didomi_token$/ },
  { name: 'iubenda', html: /iubenda\.com|_iub_cs|iubenda_cs/i, cookie: /^_iub_cs/ },
];

function detectCmp(urls: string[], html: string, cookies: string[]): string | undefined {
  const urlText = urls.join('\n');
  for (const c of CMP_PATTERNS) {
    if (c.html.test(urlText) || c.html.test(html) || (c.cookie && cookies.some((n) => c.cookie!.test(n)))) return c.name;
  }
  return undefined;
}

const GOOGLE_PING_IDS = new Set(['google-analytics', 'google-ads']);

function consentDenied(url: string): boolean {
  try {
    return new URL(url).searchParams.get('gcs') === 'G100';
  } catch {
    return false;
  }
}

/** Tracking requests and cookies that exist before any interaction with a consent banner. Needs a rendered page. */
export const privacyConsentBeforeTracking: CheckModule = {
  manifest: {
    id: 'privacy.consent-before-tracking',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'privacy',
    requires: [],
    uses: ['artifact:render', 'artifact:page'],
    provides: ['fact:privacy.cmp'],
    params: {},
    budget: {},
  },
  run(ctx): ModuleResult {
    const m = privacyConsentBeforeTracking.manifest;
    const render = getRender(ctx);
    if (!render) return {};
    const page = getPage(ctx);
    const pageHost = pageHostOf(ctx, page, render);
    const loc = { url: render.finalUrl };

    const trackers = new Map<string, ThirdPartyService>();
    const googlePings: string[] = [];
    let otherTracking = false;
    for (const r of render.requests) {
      const c = classifyHost(r.url, pageHost);
      if (!c || isUnknown(c) || !c.tracking) continue;
      trackers.set(c.id, c);
      if (GOOGLE_PING_IDS.has(c.id)) googlePings.push(r.url);
      else otherTracking = true;
    }
    const cookieNames = render.cookies.map((c) => c.name);
    const trackingCookies = [...new Set(cookieNames.filter((n) => TRACKING_COOKIE.test(n)))].sort();
    const cmp = detectCmp(render.requests.map((r) => r.url), render.html + '\n' + (page?.html ?? ''), cookieNames);
    const cmpVar = cmp ?? '–';

    const findings: Finding[] = [];
    if (trackers.size) {
      const list = joinList([...trackers.values()].map(label));
      const denied = !otherTracking && googlePings.length > 0 && googlePings.every(consentDenied) && !trackingCookies.length;
      findings.push(
        denied
          ? finding(m, { kind: 'consent-mode-denied', severity: 'info', confidence: 'confirmed', location: loc, messageKey: 'privacy.consent-mode-denied', vars: { list, cmp: cmpVar } })
          : finding(m, { kind: 'tracking-before-consent', severity: 'medium', confidence: 'confirmed', location: loc, messageKey: 'privacy.tracking-before-consent', vars: { list, cmp: cmpVar } }),
      );
    }
    if (trackingCookies.length) {
      findings.push(
        finding(m, { kind: 'cookies-before-consent', severity: 'medium', confidence: 'confirmed', location: loc, messageKey: 'privacy.cookies-before-consent', vars: { list: joinList(trackingCookies), cmp: cmpVar } }),
      );
    }
    return { findings, ...(cmp ? { facts: { 'privacy.cmp': cmp } } : {}) };
  },
};

export const privacyModules: CheckModule[] = [privacyThirdParty, privacyGoogleFonts, privacyConsentBeforeTracking];
