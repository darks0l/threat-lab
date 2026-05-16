/**
 * Pattern Library — persistent, IPFS-ready storage for threat findings.
 * The library grows smarter with every submission.
 */
import { readFile, writeFile, mkdir } from 'fs/promises';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
const __dirname = dirname(fileURLToPath(import.meta.url));
const LIBRARY_DIR = resolve(__dirname, '..', 'library');
// ── Storage ───────────────────────────────────────────────────────────────────
async function ensureLibraryDir() {
    await mkdir(LIBRARY_DIR, { recursive: true });
    await mkdir(resolve(LIBRARY_DIR, 'reports'), { recursive: true });
    await mkdir(resolve(LIBRARY_DIR, 'submissions'), { recursive: true });
}
async function getIndexPath() {
    await ensureLibraryDir();
    return resolve(LIBRARY_DIR, 'index.json');
}
async function loadIndex() {
    const indexPath = await getIndexPath();
    try {
        const data = await readFile(indexPath, 'utf-8');
        return JSON.parse(data);
    }
    catch {
        return [];
    }
}
async function saveIndex(entries) {
    const indexPath = await getIndexPath();
    await writeFile(indexPath, JSON.stringify(entries, null, 2), 'utf-8');
}
// ── Library operations ─────────────────────────────────────────────────────────
/**
 * Add a new submission to the pattern library.
 */
export async function addToLibrary(report, metadata) {
    await ensureLibraryDir();
    const index = await loadIndex();
    const entry = {
        id: randomUUID(),
        reportId: report.reportId,
        scenarioId: report.scenarioId,
        scenarioName: report.scenarioId, // Will be resolved by caller
        attackPattern: report.attackPattern,
        severity: report.severity,
        summary: report.summary,
        findings: report.findings,
        recommendations: report.recommendations,
        confidence: report.confidence,
        submittedBy: metadata.submittedBy,
        submittedAt: new Date().toISOString(),
        txHashes: metadata.txHashes ?? [],
        chainId: metadata.chainId ?? 1,
        viewCount: 0,
        citationCount: 0,
    };
    index.push(entry);
    await saveIndex(index);
    // Also save the full report
    await writeFile(resolve(LIBRARY_DIR, 'reports', `${report.reportId}.json`), JSON.stringify(report, null, 2), 'utf-8');
    console.log(`\n📚 Added to pattern library:`);
    console.log(`   ID: ${entry.id}`);
    console.log(`   Pattern: ${entry.attackPattern} | Severity: ${entry.severity}`);
    console.log(`   Confidence: ${(entry.confidence * 100).toFixed(0)}%`);
    console.log(`   Library size: ${index.length} entries`);
    return entry;
}
/**
 * Search the library by pattern, severity, or keyword.
 */
export async function searchLibrary(query) {
    const index = await loadIndex();
    let results = index;
    if (query.pattern) {
        results = results.filter(e => e.attackPattern === query.pattern);
    }
    if (query.severity) {
        results = results.filter(e => e.severity === query.severity);
    }
    if (query.keyword) {
        const kw = query.keyword.toLowerCase();
        results = results.filter(e => e.summary.toLowerCase().includes(kw) ||
            e.scenarioName.toLowerCase().includes(kw) ||
            e.findings.some(f => f.title.toLowerCase().includes(kw) || f.description.toLowerCase().includes(kw)));
    }
    if (query.minConfidence !== undefined) {
        results = results.filter(e => e.confidence >= query.minConfidence);
    }
    return results.slice(0, query.limit ?? 50);
}
/**
 * Get similar entries from the library based on attack pattern.
 */
export async function findSimilar(pattern, limit = 3) {
    const index = await loadIndex();
    return index
        .filter(e => e.attackPattern === pattern)
        .sort((a, b) => b.confidence - a.confidence)
        .slice(0, limit);
}
/**
 * Get the full library stats.
 */
export async function getLibraryStats() {
    const index = await loadIndex();
    const byPattern = {};
    const bySeverity = {};
    let totalConfidence = 0;
    for (const entry of index) {
        byPattern[entry.attackPattern] = (byPattern[entry.attackPattern] ?? 0) + 1;
        bySeverity[entry.severity] = (bySeverity[entry.severity] ?? 0) + 1;
        totalConfidence += entry.confidence;
    }
    return {
        totalEntries: index.length,
        byPattern,
        bySeverity,
        avgConfidence: index.length > 0 ? totalConfidence / index.length : 0,
        newestEntry: index.length > 0 ? index[index.length - 1].submittedAt : null,
    };
}
/**
 * Get all unique attack patterns in the library.
 */
export async function getPatternCounts() {
    const index = await loadIndex();
    const counts = {};
    for (const entry of index) {
        counts[entry.attackPattern] = (counts[entry.attackPattern] ?? 0) + 1;
    }
    return counts;
}
/**
 * Get the full list of all entries.
 */
export async function getLibrary() {
    return loadIndex();
}
/**
 * Increment the view count for an entry.
 */
export async function trackView(id) {
    const index = await loadIndex();
    const entry = index.find(e => e.id === id);
    if (entry) {
        entry.viewCount++;
        await saveIndex(index);
    }
}
/**
 * Export the full library as a single JSON blob (IPFS-ready).
 */
export async function exportLibrary() {
    const index = await loadIndex();
    const exportData = {
        version: '1.0',
        exportedAt: new Date().toISOString(),
        totalEntries: index.length,
        entries: index,
    };
    return JSON.stringify(exportData, null, 2);
}
/**
 * Import entries from a previous export.
 */
export async function importLibrary(jsonData) {
    const data = JSON.parse(jsonData);
    const index = await loadIndex();
    const existingIds = new Set(index.map(e => e.id));
    const newEntries = data.entries.filter(e => !existingIds.has(e.id));
    index.push(...newEntries);
    await saveIndex(index);
    return newEntries.length;
}
//# sourceMappingURL=library.js.map