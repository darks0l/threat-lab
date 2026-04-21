/**
 * Threat Lab — Live Threat Intelligence
 *
 * Layer 2b of the unified scan: after checking static vulnerability databases,
 * this module does live web searches to catch:
 * - 0-days not yet in CVE/OSV databases
 * - Active discussions on X/Twitter
 * - GitHub Security Advisories published recently
 * - Security blog posts about recent discoveries
 *
 * Uses Brave Search API + GitHub Security Advisories API.
 * Requires BRAVE_SEARCH_API_KEY environment variable.
 */

import axios from 'axios';

// ── Constants ─────────────────────────────────────────────────────────────────

const BRAVE_API = 'https://api.search.brave.com/res/v1/web/search';
const GH_ADVISORIES_API = 'https://api.github.com/advisories';
const DAYS_LOOKBACK = 14; // search last 14 days

// Keywords that indicate an active/exploited vulnerability
const ALERT_KEYWORDS = [
  'actively exploited',
  'in the wild',
  'weaponized',
  'poc available',
  'public exploit',
  'zero-day',
  '0day',
  '0-day',
  'being exploited',
  'critical vulnerability',
  'remote code execution',
];

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ThreatIntelResult {
  packageName: string;
  packageVersion: string;
  searches: SearchResult[];
  overallSeverity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  hasActiveExploit: boolean;
  summary: string;
  recommendations: string[];
}

export interface SearchResult {
  source: 'twitter' | 'github-advisory' | 'security-blog' | 'general';
  query: string;
  resultCount: number;
  findings: WebFinding[];
  freshestDate: string | null; // ISO date of most recent result
}

export interface WebFinding {
  title: string;
  url: string;
  date: string | null; // ISO date or null if not available
  snippet: string;
  source: string;
  isAlert: boolean; // true if matches ALERT_KEYWORDS
}

// ── Main entry point ──────────────────────────────────────────────────────────

export interface ThreatIntelOptions {
  packages: Array<{ name: string; version: string }>;
  braveApiKey?: string;
  ghToken?: string;
  daysLookback?: number;
}

/**
 * For each package, run live searches across multiple sources.
 * Returns per-package threat intelligence results.
 */
export async function runThreatIntel(
  options: ThreatIntelOptions,
): Promise<ThreatIntelResult[]> {
  const {
    packages,
    braveApiKey = process.env.BRAVE_SEARCH_API_KEY ?? '',
    ghToken = process.env.GITHUB_TOKEN ?? '',
    daysLookback = DAYS_LOOKBACK,
  } = options;

  const results: ThreatIntelResult[] = [];

  console.log('\n🌐 Running live threat intelligence...');

  for (const pkg of packages) {
    const searches: SearchResult[] = [];
    let hasActiveExploit = false;
    let allFindings: WebFinding[] = [];

    // ── GitHub Security Advisories (free, no API key needed for public data) ──
    if (ghToken) {
      const ghResult = await searchGitHubAdvisories(pkg.name, ghToken, daysLookback);
      searches.push(ghResult);
      allFindings.push(...ghResult.findings);
      if (ghResult.findings.some(f => f.isAlert)) hasActiveExploit = true;
    } else {
      searches.push({
        source: 'github-advisory',
        query: pkg.name,
        resultCount: 0,
        findings: [],
        freshestDate: null,
      });
    }

    // ── Brave Search (requires API key) ──
    if (braveApiKey) {
      const braveResult = await searchBrave(pkg.name, pkg.version, braveApiKey, daysLookback);
      searches.push(braveResult);
      allFindings.push(...braveResult.findings);
      if (braveResult.findings.some(f => f.isAlert)) hasActiveExploit = true;
    } else {
      searches.push({
        source: 'general',
        query: pkg.name,
        resultCount: 0,
        findings: [],
        freshestDate: null,
      });
      if (braveApiKey === '') {
        console.log(`   ⚠️  BRAVE_SEARCH_API_KEY not set — live web search skipped (get key at brave.com/search/api)`);
      }
    }

    // ── Overall severity ──
    const alertFindings = allFindings.filter(f => f.isAlert);
    const recentFindings = allFindings.filter(f => {
      if (!f.date) return false;
      const d = new Date(f.date);
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - daysLookback);
      return d > cutoff;
    });

    let overallSeverity: ThreatIntelResult['overallSeverity'] = 'none';
    if (alertFindings.length > 0) overallSeverity = 'critical';
    else if (recentFindings.length >= 3) overallSeverity = 'high';
    else if (recentFindings.length > 0) overallSeverity = 'medium';
    else if (allFindings.length > 0) overallSeverity = 'low';

    const recommendations: string[] = [];
    if (overallSeverity === 'critical') {
      recommendations.push(`🚨 ACTIVE EXPLOIT: "${pkg.name}" has live exploit discussion online — do NOT use until confirmed safe`);
    } else if (overallSeverity === 'high') {
      recommendations.push(`⚠️ Multiple recent reports about "${pkg.name}" — investigate before production use`);
    }

    results.push({
      packageName: pkg.name,
      packageVersion: pkg.version,
      searches,
      overallSeverity,
      hasActiveExploit,
      summary: buildSummary(pkg.name, searches, allFindings, daysLookback),
      recommendations,
    });

    // Per-package console output
    const sevIcon = overallSeverity === 'critical' ? '🔴' : overallSeverity === 'high' ? '🟠' : overallSeverity === 'medium' ? '🟡' : overallSeverity === 'low' ? '🟢' : '⚪';
    const ghCount = searches.find(s => s.source === 'github-advisory')?.resultCount ?? 0;
    const webCount = searches.find(s => s.source !== 'github-advisory')?.resultCount ?? 0;
    console.log(
      `   ${sevIcon} ${pkg.name}@${pkg.version}: ` +
      `GH advisories: ${ghCount} | Web: ${webCount} → ${overallSeverity}`,
    );
  }

  return results;
}

// ── GitHub Security Advisories ────────────────────────────────────────────────

async function searchGitHubAdvisories(
  packageName: string,
  token: string,
  days: number,
): Promise<SearchResult> {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  const since = cutoff.toISOString().split('T')[0]; // YYYY-MM-DD

  const findings: WebFinding[] = [];

  try {
    // GitHub's global security advisories database — free with GH token
    const resp = await axios.get(`${GH_ADVISORIES_API}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28',
      },
      params: {
        query: packageName,
        severity: 'high,critical',
        published_after: since,
        per_page: 10,
      },
      timeout: 15_000,
    });

    const advisories: Array<{
      ghsa_id: string;
      summary: string;
      description?: string;
      severity?: string;
      published_at: string;
      html_url: string;
      vulnerabilities?: Array<{ package: { ecosystem: string; name: string } }>;
    }> = resp.data?.advisories ?? [];

    for (const adv of advisories) {
      // Filter to npm ecosystem only
      const isNpm = adv.vulnerabilities?.some(
        v => v.package?.ecosystem?.toLowerCase() === 'npm'
          && v.package?.name?.toLowerCase() === packageName.toLowerCase(),
      );
      if (!isNpm && advisories.length > 0) {
        // If no ecosystem filter matched, check by keyword in summary
        const summaryLower = adv.summary.toLowerCase();
        const pkgLower = packageName.toLowerCase();
        if (!summaryLower.includes(pkgLower) && !pkgLower.includes(summaryLower.split(' ')[0])) {
          continue; // not a match for this package
        }
      }

      const description = adv.description ?? '';
      const isAlert = ALERT_KEYWORDS.some(k =>
        adv.summary.toLowerCase().includes(k) || description.toLowerCase().includes(k),
      );

      findings.push({
        title: adv.summary,
        url: adv.html_url,
        date: adv.published_at,
        snippet: description.slice(0, 300),
        source: 'GitHub Security Advisories',
        isAlert,
      });
    }
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 403) {
      console.warn(`   ⚠️  GitHub API rate limited — advisory search skipped`);
    } else {
      console.warn(`   ⚠️  GitHub advisory search failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const freshestDate = findings
    .filter(f => f.date)
    .sort((a, b) => new Date(b.date!).getTime() - new Date(a.date!).getTime())[0]?.date ?? null;

  return {
    source: 'github-advisory',
    query: packageName,
    resultCount: findings.length,
    findings,
    freshestDate,
  };
}

// ── Brave Search ──────────────────────────────────────────────────────────────

async function searchBrave(
  packageName: string,
  version: string,
  apiKey: string,
  days: number,
): Promise<SearchResult> {
  const findings: WebFinding[] = [];
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  const since = cutoff.toISOString().split('T')[0];

  const queries = [
    `${packageName} vulnerability 2026`,
    `${packageName} security exploit 2026`,
    `${packageName} CVE 2026`,
  ];

  for (const query of queries) {
    try {
      const resp = await axios.get(BRAVE_API, {
        headers: {
          Accept: 'application/json',
          'X-Swae-Client-Name': 'threat-lab',
          'X-Swae-Client-Version': '0.1.0',
          Authorization: `Bearer ${apiKey}`,
        },
        params: {
          q: query,
          count: 5,
          freshness: `pd-${since}`,
        },
        timeout: 15_000,
      });

      const web: Array<{
        title?: string;
        url?: string;
        description?: string;
        age?: string;
        page_age?: { datetime?: string };
      }> = resp.data?.web?.results ?? [];

      for (const result of web) {
        const title = result.title ?? '';
        const snippet = result.description ?? '';
        const text = `${title} ${snippet}`;
        const isAlert = ALERT_KEYWORDS.some(k => text.toLowerCase().includes(k));

        // Try to extract a date
        let date: string | null = null;
        if (result.page_age?.datetime) {
          date = result.page_age.datetime;
        } else if (result.age) {
          date = parseBraveAge(result.age);
        }

        // Determine source
        const url = result.url ?? '';
        let source: SearchResult['source'] = 'general';
        if (url.includes('twitter.com') || url.includes('x.com')) source = 'twitter';
        else if (url.includes('github.com/advisory') || url.includes('github.com/security')) source = 'github-advisory';
        else if (/security|exploit|cve|vulnerability|advisory/i.test(url)) source = 'security-blog';

        findings.push({
          title,
          url,
          date,
          snippet: snippet.slice(0, 300),
          source,
          isAlert,
        });
      }
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 401) {
        console.warn(`   ⚠️  Brave Search API key invalid — live web search skipped`);
        break;
      }
      // Non-blocking — individual query failures don't stop the scan
    }
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  const unique = findings.filter(f => {
    if (seen.has(f.url)) return false;
    seen.add(f.url);
    return true;
  });

  const freshestDate = unique
    .filter(f => f.date)
    .sort((a, b) => new Date(b.date!).getTime() - new Date(a.date!).getTime())[0]?.date ?? null;

  return {
    source: 'general',
    query: queries.join(' | '),
    resultCount: unique.length,
    findings: unique,
    freshestDate,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseBraveAge(age: string): string | null {
  // Brave returns ages like "2 days ago", "3 weeks ago"
  const match = age.match(/(\d+)\s+(day|week|month|year)/i);
  if (!match) return null;
  const n = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  const date = new Date();
  if (unit.startsWith('day')) date.setDate(date.getDate() - n);
  else if (unit.startsWith('week')) date.setDate(date.getDate() - n * 7);
  else if (unit.startsWith('month')) date.setMonth(date.getMonth() - n);
  else if (unit.startsWith('year')) date.setFullYear(date.getFullYear() - n);
  return date.toISOString();
}

function buildSummary(
  packageName: string,
  searches: SearchResult[],
  findings: WebFinding[],
  days: number,
): string {
  const ghCount = searches.find(s => s.source === 'github-advisory')?.resultCount ?? 0;
  const webCount = findings.filter(f => f.source !== 'github-advisory').length;
  const alertCount = findings.filter(f => f.isAlert).length;

  if (alertCount > 0) {
    return `🚨 ${alertCount} active exploit discussion(s) found for "${packageName}" in the last ${days} days`;
  }
  if (ghCount > 0 && webCount > 0) {
    return `${ghCount} GitHub advisory(ies) and ${webCount} web mention(s) found for "${packageName}" in the last ${days} days`;
  }
  if (ghCount > 0) {
    return `${ghCount} recent GitHub security advisory(ies) for "${packageName}" in the last ${days} days`;
  }
  if (webCount > 0) {
    return `${webCount} web mention(s) found for "${packageName}" in the last ${days} days`;
  }
  return `No recent threat intelligence found for "${packageName}" in the last ${days} days`;
}
