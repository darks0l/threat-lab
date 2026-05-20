import { describe, it, expect, vi, afterEach } from 'vitest';
import axios from 'axios';

vi.mock('axios');
const mockedAxios = vi.mocked(axios, true);

describe('threatIntel GitHub advisory behavior', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('queries GitHub advisories even without GITHUB_TOKEN', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { advisories: [] } } as never);

    const { runThreatIntel } = await import('../src/threatIntel.js');
    await runThreatIntel({
      packages: [{ name: 'ethers', version: '6.13.0' }],
      braveApiKey: '',
      ghToken: '',
      daysLookback: 14,
    });

    expect(mockedAxios.get).toHaveBeenCalled();
    const call = mockedAxios.get.mock.calls[0];
    expect(call?.[0]).toContain('api.github.com/advisories');
    expect(call?.[1]?.headers?.Authorization).toBeUndefined();
  });

  it('includes Authorization header when GITHUB_TOKEN is provided', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { advisories: [] } } as never);

    const { runThreatIntel } = await import('../src/threatIntel.js');
    await runThreatIntel({
      packages: [{ name: 'axios', version: '1.7.0' }],
      braveApiKey: '',
      ghToken: 'ghp_test_token',
      daysLookback: 14,
    });

    const call = mockedAxios.get.mock.calls[0];
    expect(call?.[1]?.headers?.Authorization).toBe('Bearer ghp_test_token');
  });
});
