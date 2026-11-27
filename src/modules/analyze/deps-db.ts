// Known-vulnerable client-side libraries.
// Stand: 20.11.2026, curated, not exhaustive.
// Data only. Ranges are [introduced, fixed): introduced inclusive (null = from the start), fixed exclusive.
// Only advisories that are well known are listed; a missing entry does not mean a version is free of issues.

export type DbSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface VersionRange {
  /** Inclusive lower bound, null = no lower bound. */
  from: string | null;
  /** Exclusive upper bound = first fixed version. */
  to: string;
}

export interface AdvisoryRule {
  ranges: VersionRange[];
  severity: DbSeverity;
  /** Advisory ids (CVE). */
  ids: string[];
  /** Where the advisories can be read. */
  source: string;
}

export interface LibraryEntry {
  /** Normalised library name, also used in the finding kind ('lib-<name>'). */
  name: string;
  rules: AdvisoryRule[];
}

export interface EolEntry {
  name: string;
  /** Applies to versions >= from and < to. */
  from: string;
  to: string;
  /** YYYY-MM */
  eol: string;
  severity: 'medium' | 'low';
  source: string;
}

const r = (from: string | null, to: string): VersionRange => ({ from, to });

export const VULN_DB: LibraryEntry[] = [
  {
    name: 'jquery',
    rules: [
      {
        ranges: [r(null, '3.5.0')],
        severity: 'medium',
        ids: ['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2019-11358'],
        source: 'https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/',
      },
    ],
  },
  {
    name: 'jquery-ui',
    rules: [
      {
        ranges: [r(null, '1.13.2')],
        severity: 'medium',
        ids: ['CVE-2021-41182', 'CVE-2021-41183', 'CVE-2021-41184', 'CVE-2022-31160'],
        source: 'https://github.com/jquery/jquery-ui/security/advisories',
      },
    ],
  },
  {
    name: 'bootstrap',
    rules: [
      {
        ranges: [r(null, '3.4.1'), r('4.0.0', '4.3.1')],
        severity: 'medium',
        ids: ['CVE-2019-8331'],
        source: 'https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/',
      },
      {
        ranges: [r(null, '3.4.0'), r('4.0.0', '4.1.2')],
        severity: 'medium',
        ids: ['CVE-2018-14040', 'CVE-2018-14041', 'CVE-2018-14042'],
        source: 'https://blog.getbootstrap.com/2018/07/12/bootstrap-3-4-0-and-4-1-2/',
      },
    ],
  },
  {
    name: 'lodash',
    rules: [
      {
        ranges: [r(null, '4.17.21')],
        severity: 'medium',
        ids: ['CVE-2021-23337', 'CVE-2020-8203', 'CVE-2019-10744'],
        source: 'https://github.com/lodash/lodash/security/advisories',
      },
    ],
  },
  {
    name: 'moment',
    rules: [
      {
        ranges: [r(null, '2.29.4')],
        severity: 'low',
        ids: ['CVE-2022-31129', 'CVE-2022-24785'],
        source: 'https://github.com/moment/moment/security/advisories',
      },
    ],
  },
  {
    name: 'dompurify',
    rules: [
      {
        ranges: [r(null, '2.5.4'), r('3.0.0', '3.1.3')],
        severity: 'high',
        ids: ['CVE-2024-45801', 'CVE-2024-47875'],
        source: 'https://github.com/cure53/DOMPurify/security/advisories',
      },
      {
        ranges: [r(null, '2.5.4'), r('3.0.0', '3.2.4')],
        severity: 'medium',
        ids: ['CVE-2025-26791'],
        source: 'https://github.com/cure53/DOMPurify/security/advisories',
      },
    ],
  },
  {
    name: 'axios',
    rules: [
      {
        ranges: [r(null, '0.28.0'), r('1.0.0', '1.6.0')],
        severity: 'medium',
        ids: ['CVE-2023-45857'],
        source: 'https://github.com/axios/axios/security/advisories',
      },
    ],
  },
  {
    name: 'nextjs',
    rules: [
      {
        ranges: [r('11.1.4', '12.3.5'), r('13.0.0', '13.5.9'), r('14.0.0', '14.2.25'), r('15.0.0', '15.2.3')],
        severity: 'high',
        ids: ['CVE-2025-29927'],
        source: 'https://github.com/vercel/next.js/security/advisories',
      },
      {
        ranges: [
          r('15.0.0', '15.0.5'),
          r('15.1.0', '15.1.9'),
          r('15.2.0', '15.2.6'),
          r('15.3.0', '15.3.6'),
          r('15.4.0', '15.4.8'),
          r('15.5.0', '15.5.7'),
          r('16.0.0', '16.0.7'),
        ],
        severity: 'critical',
        ids: ['CVE-2025-66478', 'CVE-2025-55182'],
        source: 'https://github.com/vercel/next.js/security/advisories',
      },
      {
        // Vercel release of 2026-08-25: two critical unauthenticated RCE issues (AVIF/libheif heap overflow, Windows path traversal), fixed in 15.5.24 and 16.3.3.
        // The id list is joined with ', ' for the finding text, so the descriptive label is the second entry.
        ranges: [r('15.0.0', '15.5.24'), r('16.0.0', '16.3.3')],
        severity: 'high',
        ids: ['CVE-2026-75604', 'AVIF/libheif RCE (Aug 2026)'],
        source: 'https://github.com/vercel/next.js/security/advisories',
      },
    ],
  },
];

/** PHP releases fixed for PHP2Shell, and branches without support. Stand: 20.11.2026. */
export interface ServerDb {
  php: {
    advisories: string[];
    /** Advisory of 2026-10-21, CVSS 9.2. */
    sources: string[];
    /** First fixed release per branch. Branches <= 8.1 have no official fix. */
    fixed: Record<string, string>;
    /** Highest branch without any official fix (all versions up to and including it are affected). */
    unfixedUpTo: string;
    /** Branches without security support: branch -> YYYY-MM the support ended. */
    eol: Record<string, string>;
    /** Branches whose security support ends soon: branch -> YYYY-MM. */
    eolSoon: Record<string, string>;
    eolSource: string;
  };
}

export const SERVER_DB: ServerDb = {
  php: {
    advisories: ['CVE-2026-109618', 'CVE-2026-109619'],
    sources: ['https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/', 'https://github.com/NCSC-NL/php2shell'],
    fixed: { '8.5': '8.5.12', '8.4': '8.4.27', '8.3': '8.3.36', '8.2': '8.2.35' },
    unfixedUpTo: '8.1',
    eol: { '8.1': '2025-12', '8.0': '2023-11', '7.4': '2022-11', '7.3': '2021-12', '7.2': '2020-11', '7.1': '2019-12', '7.0': '2019-01', '5.6': '2018-12' },
    eolSoon: { '8.2': '2026-12' },
    eolSource: 'https://www.php.net/supported-versions.php',
  },
};

export const EOL_DB: EolEntry[] = [
  { name: 'angularjs', from: '1.0.0', to: '2.0.0', eol: '2021-12', severity: 'medium', source: 'https://docs.angularjs.org/misc/version-support-status' },
  { name: 'vue2', from: '2.0.0', to: '3.0.0', eol: '2023-12', severity: 'low', source: 'https://v2.vuejs.org/eol/' },
];
