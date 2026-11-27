// Stand: 20.11.2026, curated, not exhaustive.
// Third-party services recognised by host suffix (and optionally a path prefix).
// `country` is the ISO code of the company's seat; for services with an explicit EU data
// region (PostHog EU, Sentry DE, Amplitude EU) it is the region. `tracking` marks services
// whose purpose is tracking/profiling (analytics, ads, session replay). Cookieless
// privacy-first analytics (Plausible, Fathom, Vercel, Cloudflare Insights) are not flagged.
import { sameSite } from '../util.ts';

export type ServiceCategory =
  | 'analytics' | 'ads' | 'tag-manager' | 'session-replay' | 'chat' | 'fonts' | 'cdn' | 'maps' | 'video'
  | 'payments' | 'auth' | 'backend' | 'error-monitoring' | 'consent' | 'ai' | 'social' | 'other';

export interface ThirdPartyService {
  id: string;
  name: string;
  company: string;
  country: string;
  category: ServiceCategory;
  tracking: boolean;
  /** Host suffixes: 'example.com' matches example.com and any subdomain. */
  hosts: string[];
  /** Optional path prefix the URL must start with. */
  path?: string;
}

export interface UnknownThirdParty {
  unknown: true;
  host: string;
}

type Def = [id: string, name: string, company: string, country: string, category: ServiceCategory, tracking: boolean, hosts: string[], path?: string];

const DEFS: Def[] = [
  ['google-analytics', 'Google Analytics', 'Google LLC', 'US', 'analytics', true, ['google-analytics.com', 'analytics.google.com']],
  ['google-tag-manager', 'Google Tag Manager', 'Google LLC', 'US', 'tag-manager', false, ['googletagmanager.com']],
  ['google-ads', 'Google Ads / DoubleClick', 'Google LLC', 'US', 'ads', true, ['doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'googleads.g.doubleclick.net']],
  ['google-fonts', 'Google Fonts', 'Google LLC', 'US', 'fonts', false, ['fonts.googleapis.com', 'fonts.gstatic.com']],
  ['google-maps', 'Google Maps', 'Google LLC', 'US', 'maps', false, ['maps.googleapis.com', 'maps.google.com', 'maps.gstatic.com']],
  ['google-maps-embed', 'Google Maps', 'Google LLC', 'US', 'maps', false, ['google.com'], '/maps'],
  ['google-recaptcha', 'Google reCAPTCHA', 'Google LLC', 'US', 'other', false, ['google.com', 'gstatic.com', 'recaptcha.net'], '/recaptcha'],
  ['youtube', 'YouTube', 'Google LLC', 'US', 'video', false, ['youtube.com', 'ytimg.com', 'youtube-nocookie.com', 'googlevideo.com']],
  ['firebase', 'Firebase', 'Google LLC', 'US', 'backend', false, ['firebaseio.com', 'firebaseapp.com', 'firebase.googleapis.com', 'firestore.googleapis.com', 'identitytoolkit.googleapis.com', 'securetoken.googleapis.com', 'firebaseinstallations.googleapis.com']],
  ['google-apis', 'Google APIs', 'Google LLC', 'US', 'other', false, ['googleapis.com']],
  ['meta-pixel', 'Meta Pixel', 'Meta Platforms, Inc.', 'US', 'ads', true, ['connect.facebook.net']],
  ['meta-pixel-tr', 'Meta Pixel', 'Meta Platforms, Inc.', 'US', 'ads', true, ['facebook.com'], '/tr'],
  ['tiktok-pixel', 'TikTok Pixel', 'TikTok Pte. Ltd.', 'SG', 'ads', true, ['analytics.tiktok.com', 'business-api.tiktok.com']],
  ['linkedin-insight', 'LinkedIn Insight Tag', 'LinkedIn Corporation', 'US', 'ads', true, ['snap.licdn.com', 'px.ads.linkedin.com']],
  ['x-pixel', 'X (Twitter) Pixel', 'X Corp.', 'US', 'ads', true, ['static.ads-twitter.com', 'analytics.twitter.com', 'ads-twitter.com']],
  ['pinterest', 'Pinterest Tag', 'Pinterest, Inc.', 'US', 'ads', true, ['ct.pinterest.com', 's.pinimg.com']],
  ['microsoft-clarity', 'Microsoft Clarity', 'Microsoft Corporation', 'US', 'session-replay', true, ['clarity.ms']],
  ['bing-uet', 'Microsoft Advertising (UET)', 'Microsoft Corporation', 'US', 'ads', true, ['bat.bing.com', 'bat.r.msn.com']],
  ['hotjar', 'Hotjar', 'Hotjar Ltd.', 'MT', 'session-replay', true, ['hotjar.com', 'hotjar.io']],
  ['mixpanel', 'Mixpanel', 'Mixpanel, Inc.', 'US', 'analytics', true, ['mixpanel.com', 'mxpnl.com']],
  ['amplitude', 'Amplitude', 'Amplitude, Inc.', 'US', 'analytics', true, ['amplitude.com']],
  ['amplitude-eu', 'Amplitude (EU)', 'Amplitude, Inc.', 'DE', 'analytics', true, ['api.eu.amplitude.com', 'sr-client-cfg.eu.amplitude.com']],
  ['segment', 'Segment', 'Twilio Inc.', 'US', 'analytics', true, ['segment.com', 'segment.io']],
  ['posthog', 'PostHog', 'PostHog, Inc.', 'US', 'analytics', true, ['posthog.com']],
  ['posthog-eu', 'PostHog (EU)', 'PostHog, Inc.', 'DE', 'analytics', true, ['eu.i.posthog.com', 'eu.posthog.com', 'eu-assets.i.posthog.com']],
  ['plausible', 'Plausible', 'Plausible Insights OÜ', 'EE', 'analytics', false, ['plausible.io']],
  ['matomo-cloud', 'Matomo Cloud', 'InnoCraft Ltd', 'NZ', 'analytics', true, ['matomo.cloud']],
  ['fathom', 'Fathom Analytics', 'Conva Ventures Inc.', 'CA', 'analytics', false, ['usefathom.com']],
  ['vercel-analytics', 'Vercel Analytics', 'Vercel Inc.', 'US', 'analytics', false, ['va.vercel-scripts.com', 'vercel-insights.com']],
  ['sentry-eu', 'Sentry (EU)', 'Functional Software, Inc.', 'DE', 'error-monitoring', false, ['de.sentry.io', 'ingest.de.sentry.io']],
  ['sentry', 'Sentry', 'Functional Software, Inc.', 'US', 'error-monitoring', false, ['sentry.io', 'sentry-cdn.com']],
  ['logrocket', 'LogRocket', 'LogRocket, Inc.', 'US', 'session-replay', true, ['logrocket.com', 'lr-ingest.io', 'lr-in.com', 'lr-in-prod.com', 'logrocket.io']],
  ['fullstory', 'FullStory', 'FullStory, Inc.', 'US', 'session-replay', true, ['fullstory.com']],
  ['intercom', 'Intercom', 'Intercom, Inc.', 'US', 'chat', false, ['intercom.io', 'intercomcdn.com', 'intercom.com']],
  ['crisp', 'Crisp', 'Crisp IM SAS', 'FR', 'chat', false, ['crisp.chat']],
  ['tawk', 'Tawk.to', 'tawk.to Inc.', 'US', 'chat', false, ['tawk.to']],
  ['zendesk', 'Zendesk', 'Zendesk, Inc.', 'US', 'chat', false, ['zdassets.com', 'zopim.com', 'zendesk.com']],
  ['hubspot', 'HubSpot', 'HubSpot, Inc.', 'US', 'analytics', true, ['hs-scripts.com', 'hs-analytics.net', 'hsforms.net', 'hsforms.com', 'hubspot.com', 'hs-banner.com', 'hsadspixel.net', 'usemessages.com', 'hscollectedforms.net']],
  ['cookiebot', 'Cookiebot', 'Usercentrics A/S', 'DK', 'consent', false, ['cookiebot.com']],
  ['usercentrics', 'Usercentrics', 'Usercentrics GmbH', 'DE', 'consent', false, ['usercentrics.eu', 'usercentrics.com']],
  ['onetrust', 'OneTrust', 'OneTrust LLC', 'US', 'consent', false, ['onetrust.com', 'cookielaw.org']],
  ['klaro', 'Klaro', 'KIProtect GmbH', 'DE', 'consent', false, ['kiprotect.com']],
  ['cookieyes', 'CookieYes', 'CookieYes Limited', 'GB', 'consent', false, ['cookieyes.com']],
  ['didomi', 'Didomi', 'Didomi SAS', 'FR', 'consent', false, ['didomi.io']],
  ['iubenda', 'iubenda', 'iubenda S.r.l.', 'IT', 'consent', false, ['iubenda.com']],
  ['stripe', 'Stripe', 'Stripe, Inc.', 'US', 'payments', false, ['stripe.com', 'stripe.network']],
  ['paypal', 'PayPal', 'PayPal, Inc.', 'US', 'payments', false, ['paypal.com', 'paypalobjects.com']],
  ['supabase', 'Supabase', 'Supabase, Inc.', 'US', 'backend', false, ['supabase.co', 'supabase.in']],
  ['clerk', 'Clerk', 'Clerk, Inc.', 'US', 'auth', false, ['clerk.com', 'clerk.dev', 'clerk.accounts.dev']],
  ['auth0', 'Auth0', 'Okta, Inc.', 'US', 'auth', false, ['auth0.com']],
  ['jsdelivr', 'jsDelivr', 'Prospect One', 'PL', 'cdn', false, ['jsdelivr.net']],
  ['unpkg', 'unpkg', 'unpkg.com', 'US', 'cdn', false, ['unpkg.com']],
  ['cdnjs', 'cdnjs', 'Cloudflare, Inc.', 'US', 'cdn', false, ['cdnjs.cloudflare.com']],
  ['cloudflare-insights', 'Cloudflare Web Analytics', 'Cloudflare, Inc.', 'US', 'analytics', false, ['static.cloudflareinsights.com', 'cloudflareinsights.com']],
  ['adobe-fonts', 'Adobe Fonts', 'Adobe Inc.', 'US', 'fonts', false, ['use.typekit.net', 'p.typekit.net']],
  ['lovable', 'Lovable', 'Lovable Labs', 'SE', 'other', false, ['cdn.gpteng.co', 'gpteng.co', 'lovable.dev']],
  ['vimeo', 'Vimeo', 'Vimeo, Inc.', 'US', 'video', false, ['vimeo.com', 'vimeocdn.com']],
  ['openai', 'OpenAI API', 'OpenAI, L.L.C.', 'US', 'ai', false, ['api.openai.com']],
  ['anthropic', 'Anthropic API', 'Anthropic, PBC', 'US', 'ai', false, ['api.anthropic.com']],
];

export const THIRD_PARTY_DB: readonly ThirdPartyService[] = DEFS.map(([id, name, company, country, category, tracking, hosts, path]) => ({
  id, name, company, country, category, tracking, hosts, ...(path ? { path } : {}),
}));

const EEA_CH = new Set([
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
  'IS', 'LI', 'NO', 'CH',
]);

/** True for EU/EEA member states and Switzerland. */
export function isEuEeaCh(country: string): boolean {
  return EEA_CH.has(country.toUpperCase());
}

/**
 * Classifies a request URL relative to the page host: null for the same site (or non-http URLs),
 * the matching service, or an unknown third party. The longest host suffix wins; a path match beats a plain host match.
 */
export function classifyHost(url: string, pageHost: string): ThirdPartyService | UnknownThirdParty | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || sameSite(host, pageHost)) return null;
  let best: ThirdPartyService | undefined;
  let bestScore = -1;
  for (const s of THIRD_PARTY_DB) {
    if (s.path && !(u.pathname === s.path || u.pathname.startsWith(s.path + '/'))) continue;
    for (const h of s.hosts) {
      if (host === h || host.endsWith('.' + h)) {
        const score = h.length + (s.path ? 1000 : 0);
        if (score > bestScore) {
          best = s;
          bestScore = score;
        }
      }
    }
  }
  return best ?? { unknown: true, host };
}

export function isUnknown(x: ThirdPartyService | UnknownThirdParty): x is UnknownThirdParty {
  return (x as UnknownThirdParty).unknown === true;
}
