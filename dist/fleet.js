import { mkdir, readFile, writeFile, readdir, stat } from 'fs/promises';
import { resolve, join, relative } from 'path';
import { randomUUID } from 'crypto';
import { auditDependencies } from './audit.js';
import { scanTarget, getWorstScanSeverity } from './scanner.js';
import { runThreatIntel } from './threatIntel.js';
const STATE_DIRNAME = '.threat-lab';
const REGISTRY_FILE = 'fleet.json';
const THREAT_STATE_FILE = 'threat-state.json';
const LAST_SCAN_FILE = 'fleet-last.json';
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
function severityIndex(severity) {
    return SEVERITY_ORDER.indexOf(severity);
}
function maxSeverity(values) {
    if (values.length === 0)
        return 'informational';
    return values.reduce((worst, current) => (severityIndex(current) < severityIndex(worst) ? current : worst));
}
function ensureSeverity(value) {
    const lower = String(value ?? '').toLowerCase();
    if (lower === 'critical')
        return 'critical';
    if (lower === 'high')
        return 'high';
    if (lower === 'medium' || lower === 'moderate')
        return 'medium';
    if (lower === 'low')
        return 'low';
    return 'informational';
}
function severityToScore(severity) {
    if (severity === 'critical')
        return 100;
    if (severity === 'high')
        return 75;
    if (severity === 'medium')
        return 50;
    if (severity === 'low')
        return 25;
    return 0;
}
function normalizeRepoPath(repoPath) {
    return resolve(repoPath);
}
function stateDir(cwd) {
    return join(cwd, STATE_DIRNAME);
}
async function ensureStateDir(cwd) {
    await mkdir(stateDir(cwd), { recursive: true });
}
async function loadJsonFile(filePath, fallback) {
    try {
        const raw = await readFile(filePath, 'utf-8');
        return JSON.parse(raw);
    }
    catch {
        return fallback;
    }
}
async function saveJsonFile(filePath, value) {
    await writeFile(filePath, JSON.stringify(value, null, 2), 'utf-8');
}
async function loadRegistry(cwd) {
    await ensureStateDir(cwd);
    return loadJsonFile(join(stateDir(cwd), REGISTRY_FILE), { version: '1', repos: [] });
}
async function saveRegistry(cwd, registry) {
    await ensureStateDir(cwd);
    await saveJsonFile(join(stateDir(cwd), REGISTRY_FILE), registry);
}
async function loadThreatState(cwd) {
    await ensureStateDir(cwd);
    return loadJsonFile(join(stateDir(cwd), THREAT_STATE_FILE), { version: '1', items: [] });
}
async function saveThreatState(cwd, state) {
    await ensureStateDir(cwd);
    await saveJsonFile(join(stateDir(cwd), THREAT_STATE_FILE), state);
}
export async function addFleetRepos(paths, cwd = process.cwd()) {
    const registry = await loadRegistry(cwd);
    const existing = new Map(registry.repos.map((repo) => [normalizeRepoPath(repo.path), repo]));
    const added = [];
    for (const inputPath of paths) {
        const normalized = normalizeRepoPath(inputPath);
        if (existing.has(normalized))
            continue;
        const repo = {
            id: randomUUID(),
            path: normalized,
            label: relative(cwd, normalized) || normalized,
            addedAt: new Date().toISOString(),
        };
        registry.repos.push(repo);
        existing.set(normalized, repo);
        added.push(repo);
    }
    await saveRegistry(cwd, registry);
    return added;
}
export async function listFleetRepos(cwd = process.cwd()) {
    const registry = await loadRegistry(cwd);
    return registry.repos;
}
async function loadRepoDependencies(repoPath) {
    try {
        const pkgPath = join(repoPath, 'package.json');
        const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
        const deps = [];
        for (const [kind, values] of [
            ['dependencies', pkg.dependencies ?? {}],
            ['devDependencies', pkg.devDependencies ?? {}],
            ['optionalDependencies', pkg.optionalDependencies ?? {}],
        ]) {
            for (const [name, version] of Object.entries(values)) {
                deps.push({ name, version, kind });
            }
        }
        return deps;
    }
    catch {
        return [];
    }
}
async function countSolidityFiles(target) {
    let count = 0;
    async function walk(dir) {
        const entries = await readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.name.startsWith('.'))
                continue;
            if (entry.isDirectory()) {
                if (['node_modules', 'dist', 'build', 'coverage', 'cache'].includes(entry.name))
                    continue;
                await walk(join(dir, entry.name));
                continue;
            }
            if (entry.isFile() && entry.name.endsWith('.sol'))
                count += 1;
        }
    }
    try {
        const targetStat = await stat(target);
        if (targetStat.isFile())
            return target.endsWith('.sol') ? 1 : 0;
        await walk(target);
    }
    catch {
        return 0;
    }
    return count;
}
function normalizeVersion(version) {
    return version.replace(/^[\^~><= ]+/, '').trim();
}
async function runRepoThreatIntel(packages) {
    if (packages.length === 0)
        return [];
    const unique = new Map();
    for (const pkg of packages) {
        if (!unique.has(pkg.name))
            unique.set(pkg.name, { name: pkg.name, version: normalizeVersion(pkg.version) || pkg.version });
    }
    return runThreatIntel({ packages: [...unique.values()] });
}
function depThreatLevel(summary) {
    const lower = String(summary ?? '').toLowerCase();
    if (lower === 'critical')
        return 'critical';
    if (lower === 'high')
        return 'high';
    if (lower === 'medium')
        return 'medium';
    if (lower === 'low')
        return 'low';
    return 'none';
}
function intelSeverity(results) {
    const severities = results
        .map((result) => ensureSeverity(result.overallSeverity === 'none' ? 'informational' : result.overallSeverity));
    return maxSeverity(severities);
}
function buildExposures(repos) {
    const map = new Map();
    for (const repo of repos) {
        for (const dep of repo.packages) {
            const key = dep.name.toLowerCase();
            const existing = map.get(key) ?? {
                packageName: dep.name,
                repoCount: 0,
                repos: [],
            };
            existing.repos.push({
                label: repo.repo.label,
                path: repo.repo.path,
                version: dep.version,
                kind: dep.kind,
            });
            existing.repoCount = existing.repos.length;
            map.set(key, existing);
        }
    }
    return [...map.values()].sort((a, b) => b.repoCount - a.repoCount || a.packageName.localeCompare(b.packageName));
}
function threatKey(packageName, finding) {
    return [packageName.toLowerCase(), finding.url || '', finding.title.trim().toLowerCase()].join('|');
}
function collectThreatObservations(repos) {
    const deduped = new Map();
    for (const repo of repos) {
        for (const intel of repo.threatIntel) {
            for (const search of intel.searches) {
                for (const finding of search.findings) {
                    const key = `${repo.repo.path}::${threatKey(intel.packageName, finding)}`;
                    if (deduped.has(key))
                        continue;
                    deduped.set(key, {
                        key: threatKey(intel.packageName, finding),
                        packageName: intel.packageName,
                        title: finding.title,
                        url: finding.url,
                        severity: finding.isAlert ? 'critical' : ensureSeverity(intel.overallSeverity === 'none' ? 'low' : intel.overallSeverity),
                        activeExploit: finding.isAlert || intel.hasActiveExploit,
                        correlated: true,
                        repo: repo.repo,
                    });
                }
            }
        }
    }
    return [...deduped.values()];
}
async function updateThreatState(cwd, repos) {
    const state = await loadThreatState(cwd);
    const byKey = new Map(state.items.map((item) => [item.key, item]));
    const observations = collectThreatObservations(repos);
    const newItems = [];
    const escalatedItems = [];
    const now = new Date().toISOString();
    for (const observation of observations) {
        const existing = byKey.get(observation.key);
        if (!existing) {
            const created = {
                id: randomUUID(),
                key: observation.key,
                packageName: observation.packageName,
                title: observation.title,
                url: observation.url,
                severity: observation.severity,
                activeExploit: observation.activeExploit,
                correlated: observation.correlated,
                firstSeen: now,
                lastSeen: now,
                repos: [observation.repo.path],
                repoLabels: [observation.repo.label],
                sightings: 1,
            };
            state.items.push(created);
            byKey.set(created.key, created);
            newItems.push(created);
            continue;
        }
        const previousSeverity = existing.severity;
        existing.lastSeen = now;
        existing.sightings += 1;
        existing.activeExploit = existing.activeExploit || observation.activeExploit;
        existing.correlated = existing.correlated || observation.correlated;
        if (!existing.repos.includes(observation.repo.path))
            existing.repos.push(observation.repo.path);
        if (!existing.repoLabels.includes(observation.repo.label))
            existing.repoLabels.push(observation.repo.label);
        if (severityIndex(observation.severity) < severityIndex(existing.severity)) {
            existing.severity = observation.severity;
        }
        if (severityIndex(existing.severity) < severityIndex(previousSeverity)) {
            escalatedItems.push(existing);
        }
    }
    state.items.sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
    await saveThreatState(cwd, state);
    return {
        newItems,
        escalatedItems,
        totalTracked: state.items.length,
    };
}
function repoScoreFromContracts(results) {
    if (results.length === 0)
        return 0;
    return Math.max(...results.map((result) => result.threatScore));
}
function repoSeverity(results, depLevel, intel) {
    const severities = [];
    if (results.length > 0)
        severities.push(getWorstScanSeverity(results));
    if (depLevel !== 'none')
        severities.push(depLevel === 'low' ? 'low' : depLevel === 'medium' ? 'medium' : depLevel === 'high' ? 'high' : 'critical');
    if (intel.length > 0)
        severities.push(intelSeverity(intel));
    return maxSeverity(severities);
}
async function scanRepo(repo, options) {
    const scannedAt = new Date().toISOString();
    const packages = await loadRepoDependencies(repo.path);
    const solidityFileCount = await countSolidityFiles(repo.path);
    const errors = [];
    let scanResults = [];
    if (solidityFileCount > 0) {
        try {
            const scanOptions = {
                target: repo.path,
                quick: options.quick,
                noDeps: true,
                noIntel: true,
                noSim: options.noSim,
                network: options.network,
                saveArtifacts: false,
            };
            scanResults = await scanTarget(scanOptions);
        }
        catch (err) {
            errors.push(`scan: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    let dependencyThreatLevel = 'none';
    let dependencyScore = 0;
    let advisoriesCount = 0;
    let vulnerabilitiesCount = 0;
    if (!options.noDeps && packages.length > 0) {
        try {
            const audit = await auditDependencies({
                projectPath: repo.path,
                includeDev: true,
                socketDev: true,
                runNpmAudit: true,
            });
            dependencyThreatLevel = depThreatLevel(audit.summary.threatLevel);
            dependencyScore = audit.summary.score;
            advisoriesCount = audit.osint?.findings.length ?? 0;
            vulnerabilitiesCount = audit.npmAudit?.totalVulnerabilities ?? 0;
        }
        catch (err) {
            errors.push(`deps: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    let threatIntel = [];
    if (!options.noIntel && packages.length > 0) {
        try {
            threatIntel = await runRepoThreatIntel(packages);
        }
        catch (err) {
            errors.push(`intel: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    const overallSeverity = repoSeverity(scanResults, dependencyThreatLevel, threatIntel);
    const threatScore = Math.max(repoScoreFromContracts(scanResults), dependencyScore, severityToScore(intelSeverity(threatIntel)));
    const activeThreatCount = threatIntel.filter((item) => item.hasActiveExploit).length;
    const correlatedThreatCount = activeThreatCount;
    return {
        repo,
        packages,
        solidityFileCount,
        scanResults,
        dependencyThreatLevel,
        dependencyScore,
        threatIntel,
        overallSeverity,
        threatScore,
        activeThreatCount,
        correlatedThreatCount,
        advisoriesCount,
        vulnerabilitiesCount,
        scannedAt,
        errors,
    };
}
function buildFleetMarkdown(summary) {
    const lines = [];
    const worst = maxSeverity(summary.repos.map((repo) => repo.overallSeverity));
    const sharedPackages = summary.exposures.filter((item) => item.repoCount > 1).length;
    lines.push('# Threat Lab Fleet Report');
    lines.push('');
    lines.push(`- Scanned at: ${summary.scannedAt}`);
    lines.push(`- Repos scanned: ${summary.repoCount}`);
    lines.push(`- Worst severity: ${worst.toUpperCase()}`);
    lines.push(`- Shared packages: ${sharedPackages}`);
    lines.push(`- New threat items: ${summary.threatDelta.newItems.length}`);
    lines.push(`- Escalated threat items: ${summary.threatDelta.escalatedItems.length}`);
    lines.push(`- Total tracked threat items: ${summary.threatDelta.totalTracked}`);
    lines.push('');
    lines.push('## Repos');
    for (const repo of summary.repos) {
        lines.push(`- ${repo.repo.label} — ${repo.overallSeverity.toUpperCase()} (${repo.threatScore}/100), packages=${repo.packages.length}, active-threats=${repo.activeThreatCount}, vulns=${repo.vulnerabilitiesCount}`);
    }
    lines.push('');
    lines.push('## Shared dependency exposure');
    for (const exposure of summary.exposures.filter((item) => item.repoCount > 1).slice(0, 25)) {
        lines.push(`- ${exposure.packageName} — ${exposure.repoCount} repos`);
    }
    if (!summary.exposures.some((item) => item.repoCount > 1)) {
        lines.push('- No multi-repo package overlap detected.');
    }
    lines.push('');
    lines.push('## New threat items');
    for (const item of summary.threatDelta.newItems.slice(0, 25)) {
        lines.push(`- ${item.packageName}: ${item.title} [${item.severity}]`);
    }
    if (summary.threatDelta.newItems.length === 0)
        lines.push('- None');
    return lines.join('\n');
}
async function saveFleetArtifacts(cwd, summary, outputPath) {
    await ensureStateDir(cwd);
    const defaultPath = join(stateDir(cwd), LAST_SCAN_FILE);
    await saveJsonFile(defaultPath, summary);
    if (!outputPath)
        return;
    if (outputPath.toLowerCase().endsWith('.md')) {
        await writeFile(outputPath, buildFleetMarkdown(summary), 'utf-8');
        return;
    }
    await saveJsonFile(outputPath, summary);
}
export async function scanFleet(options = {}) {
    const cwd = options.cwd ?? process.cwd();
    const registry = await loadRegistry(cwd);
    const selectedRepos = (options.targets && options.targets.length > 0)
        ? options.targets.map((target) => ({
            id: randomUUID(),
            path: normalizeRepoPath(target),
            label: relative(cwd, normalizeRepoPath(target)) || normalizeRepoPath(target),
            addedAt: new Date().toISOString(),
        }))
        : registry.repos;
    const repos = [];
    for (const repo of selectedRepos) {
        const summary = await scanRepo(repo, options);
        repos.push(summary);
    }
    const updatedRegistry = {
        version: '1',
        repos: registry.repos.map((repo) => {
            const match = repos.find((entry) => entry.repo.path === repo.path);
            return match ? { ...repo, lastScannedAt: match.scannedAt } : repo;
        }),
    };
    await saveRegistry(cwd, updatedRegistry);
    const scannedAt = new Date().toISOString();
    const exposures = buildExposures(repos);
    const threatDelta = await updateThreatState(cwd, repos);
    const summary = {
        scannedAt,
        repoCount: repos.length,
        repos: repos.sort((a, b) => severityIndex(a.overallSeverity) - severityIndex(b.overallSeverity) || b.threatScore - a.threatScore),
        exposures,
        threatDelta,
    };
    await saveFleetArtifacts(cwd, summary, options.outputPath);
    return summary;
}
export function formatFleetSummary(summary) {
    const lines = [];
    const worst = summary.repos.length > 0 ? maxSeverity(summary.repos.map((repo) => repo.overallSeverity)) : 'informational';
    const sharedPackages = summary.exposures.filter((item) => item.repoCount > 1).length;
    lines.push('');
    lines.push('╔═══════════════════════════════════════════════════════════════════╗');
    lines.push('║               📡 THREAT LAB — FLEET MONITOR REPORT             ║');
    lines.push('╚═══════════════════════════════════════════════════════════════════╝');
    lines.push('');
    lines.push(`  Repos scanned: ${summary.repoCount}  |  Worst severity: ${worst.toUpperCase()}  |  Shared packages: ${sharedPackages}`);
    lines.push(`  New threats: ${summary.threatDelta.newItems.length}  |  Escalated: ${summary.threatDelta.escalatedItems.length}  |  Tracked: ${summary.threatDelta.totalTracked}`);
    lines.push('');
    for (const repo of summary.repos) {
        const icon = repo.overallSeverity === 'critical' ? '🔴' : repo.overallSeverity === 'high' ? '🟠' : repo.overallSeverity === 'medium' ? '🟡' : repo.overallSeverity === 'low' ? '🟢' : '⚪';
        lines.push(`  ${icon} ${repo.repo.label}`);
        lines.push(`     score=${repo.threatScore}/100 | packages=${repo.packages.length} | sol=${repo.solidityFileCount} | active-threats=${repo.activeThreatCount} | vulns=${repo.vulnerabilitiesCount}`);
        if (repo.errors.length > 0)
            lines.push(`     errors: ${repo.errors.join(' | ')}`);
    }
    lines.push('');
    lines.push('  Shared dependency exposure:');
    for (const exposure of summary.exposures.filter((item) => item.repoCount > 1).slice(0, 10)) {
        lines.push(`     • ${exposure.packageName} → ${exposure.repoCount} repos`);
    }
    if (!summary.exposures.some((item) => item.repoCount > 1))
        lines.push('     • none');
    lines.push('');
    lines.push('  New threat items:');
    for (const item of summary.threatDelta.newItems.slice(0, 10)) {
        lines.push(`     • ${item.packageName}: ${item.title} [${item.severity}]`);
    }
    if (summary.threatDelta.newItems.length === 0)
        lines.push('     • none');
    lines.push('');
    return lines.join('\n');
}
//# sourceMappingURL=fleet.js.map