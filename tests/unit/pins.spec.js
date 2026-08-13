import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    verifySmtProof,
    fetchEVMRoot,
    fetchIndexerRoot,
    verifyRootValidityOnContract,
    evmCall,
    isPIVXName,
    isPIVXNameTLD,
    PIVXNameTLDs,
} from '../../scripts/utils.pins.js';
import { mount } from '@vue/test-utils';
import PiNS from '../../scripts/dashboard/PiNS.vue';
import { Database } from '../../scripts/database.js';

vi.mock('../../scripts/i18n.js', () => {
    const translation = {
        pinsPolling: 'Polling...',
        pinsTitleSecurityWarning: 'Security Warning',
        pinsTextSecurityWarning:
            'The Name Service indexer returned a state root that has never been registered on the anchor contract.',
        pinsTitleSynced: 'Synced',
        pinsTextSynced: 'Synced success.',
        pinsTitleNotFound: 'Not Found',
        pinsTextNotFound: 'Not found.',
        pinsTitleSyncDelay: 'Sync Delay',
        pinsTextSyncDelayResolved: 'Sync delay.',
        pinsTitleSyncDelayNotFound: 'Sync Delay Not Found',
        pinsTextSyncDelayNotFound: 'Sync delay not found.',
        pinsTitleIndexerError: 'Indexer Error',
        pinsTextIndexerError: 'Error: {errMsg}',
        pinsBtnClose: 'Close',
        pinsBtnSend: 'Send',
        pinsBtnSendAnyway: 'Send anyway',
        pinsBtnCancel: 'Cancel',
        pinsBtnRetry: 'Retry',
    };
    const ALERTS = {
        PINS_RESOLVING_DOMAIN: 'Resolving {strDomain}...',
        PINS_CHECKING_SYNC: 'Checking sync...',
        PINS_SYNCING_WAIT: 'Syncing...',
        PINS_SYNC_FAILED: 'Sync failed: {errMsg}',
        PINS_RESOLVE_FAILED: 'Resolve failed: {errMsg}',
        PINS_INVALID_FORMAT: 'Invalid format',
        PINS_INCOMPLETE_METADATA: 'Incomplete metadata',
        PINS_INVALID_PROOF: 'Invalid proof',
        PINS_INVALID_SHIELD: 'Invalid shield',
        PINS_NAME_MISMATCH: 'Name mismatch',
        PINS_NOT_FOUND: 'Not found',
    };
    return {
        translation,
        ALERTS,
        tr: (message, variables) => {
            if (!message) return '';
            variables.forEach((element) => {
                message = message.replaceAll(
                    '{' + Object.keys(element)[0] + '}',
                    Object.values(element)[0]
                );
            });
            return message;
        },
        switchTranslation: vi.fn(),
    };
});

/**
 * A real answer from the production indexer for `alexxiy.pivx`, kept verbatim.
 *
 * This proof folds to `smt_root`, and that root was the anchor contract's
 * `currentRoot()` when it was captured - so the vector pins the wallet to the
 * protocol as actually deployed, not to whatever the wallet happens to compute.
 * Regenerate it with:
 *   curl -s -X POST -H 'Content-Type: application/json' -d '{}' \
 *        https://indexer.pivx.name/v1.0/resolve/alexxiy.pivx
 */
const LIVE_VECTOR = Object.freeze({
    domain_name: 'alexxiy.pivx',
    target_address:
        'ps19wd4eft4mw2mlwad6tjrny5hlvtdxymatu2e3dge7jr6scqask0llvdsa3xhx06499vmzymatxr',
    owner_pubkey:
        '3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53',
    price: 0,
    nonce: 1786604913,
    smt_root:
        '1bebbbf778b7c70d7f28af955d28c65165d9b52e2128efdcebdd6f695a773ceb',
    merkle_proof: [
        'ce7b953670410e6a28bb669dbf36c92b3a1d3be8ad1053b9dfcf730049fe57ff',
        '8de7514f0d3a019a6cb017618c3c8f2774aaf063b47a0ed1fcc52e4a7080fa71',
        '654cb451e501cb7461dd845404e9c5f7b5fc6f13b6c4763bd6c01f43d1ec50f9',
    ],
    proof_depth: 3,
    proof_terminal: 'Occupied',
});

/** A copy of the live vector with one field changed. */
const tamper = (changes) => ({ ...LIVE_VECTOR, ...changes });

describe('verifySmtProof (compact SMT)', () => {
    it('verifies a real proof from the production indexer', () => {
        expect(verifySmtProof(LIVE_VECTOR, 'alexxiy.pivx')).toBe(true);
    });

    it('accepts the name in any case, normalising once', () => {
        expect(verifySmtProof(LIVE_VECTOR, 'ALEXXIY.pivx')).toBe(true);
        expect(verifySmtProof(LIVE_VECTOR, 'Alexxiy.PIVX')).toBe(true);
    });

    it('rejects a proof folded for a different name', () => {
        expect(verifySmtProof(LIVE_VECTOR, 'alexxiy.safe')).toBe(false);
        expect(verifySmtProof(LIVE_VECTOR, 'alexxi.pivx')).toBe(false);
    });

    // Every field below is inside the leaf preimage, so changing any one of them
    // must break the fold. This is what stops a hostile indexer swapping the payout
    // address while keeping a proof that looks well formed.
    it('rejects a tampered target address', () => {
        expect(
            verifySmtProof(
                tamper({
                    target_address:
                        'ps19wd4eft4mw2mlwad6tjrny5hlvtdxymatu2e3dge7jr6scqask0llvdsa3xhx06499vmzymatxq',
                }),
                'alexxiy.pivx'
            )
        ).toBe(false);
    });

    it('rejects a tampered owner pubkey', () => {
        expect(
            verifySmtProof(
                tamper({
                    owner_pubkey:
                        '0000ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53',
                }),
                'alexxiy.pivx'
            )
        ).toBe(false);
    });

    it('rejects a tampered price or nonce', () => {
        expect(verifySmtProof(tamper({ price: 1 }), 'alexxiy.pivx')).toBe(
            false
        );
        expect(
            verifySmtProof(tamper({ nonce: 1786604914 }), 'alexxiy.pivx')
        ).toBe(false);
    });

    it('rejects a tampered sibling', () => {
        const bad = tamper({
            merkle_proof: [
                '0000953670410e6a28bb669dbf36c92b3a1d3be8ad1053b9dfcf730049fe57ff',
                LIVE_VECTOR.merkle_proof[1],
            ],
        });
        expect(verifySmtProof(bad, 'alexxiy.pivx')).toBe(false);
    });

    it('rejects a tampered root', () => {
        expect(
            verifySmtProof(
                tamper({
                    smt_root:
                        '0000bbf778b7c70d7f28af955d28c65165d9b52e2128efdcebdd6f695a773ceb',
                }),
                'alexxiy.pivx'
            )
        ).toBe(false);
    });

    // The depth is self authenticating: folding a different number of times gives a
    // different root. These cases make sure we reject rather than fold blindly.
    it('rejects when proof_depth disagrees with the sibling count', () => {
        expect(verifySmtProof(tamper({ proof_depth: 2 }), 'alexxiy.pivx')).toBe(
            false
        );
        expect(verifySmtProof(tamper({ proof_depth: 4 }), 'alexxiy.pivx')).toBe(
            false
        );
    });

    it('rejects a depth beyond the 128-bit key length', () => {
        expect(
            verifySmtProof(
                tamper({
                    proof_depth: 129,
                    merkle_proof: Array(129).fill(LIVE_VECTOR.merkle_proof[0]),
                }),
                'alexxiy.pivx'
            )
        ).toBe(false);
    });

    // A resolve is an inclusion proof. Absence is reported as "Domain not found",
    // so anything else here is malformed and must not be folded.
    it('rejects any terminal other than Occupied', () => {
        for (const terminal of ['Vacant', 'Blocked', '', undefined]) {
            expect(
                verifySmtProof(
                    tamper({ proof_terminal: terminal }),
                    'alexxiy.pivx'
                )
            ).toBe(false);
        }
    });

    it('rejects incomplete or malformed responses', () => {
        expect(verifySmtProof(null, 'alexxiy.pivx')).toBe(false);
        expect(verifySmtProof(LIVE_VECTOR, '')).toBe(false);
        expect(
            verifySmtProof(tamper({ target_address: '' }), 'alexxiy.pivx')
        ).toBe(false);
        expect(verifySmtProof(tamper({ smt_root: '' }), 'alexxiy.pivx')).toBe(
            false
        );
        expect(
            verifySmtProof(
                tamper({ merkle_proof: 'not-an-array' }),
                'alexxiy.pivx'
            )
        ).toBe(false);
        // a sibling that is not 32 bytes must be refused, not silently padded
        expect(
            verifySmtProof(
                tamper({ merkle_proof: ['abcd', LIVE_VECTOR.merkle_proof[1]] }),
                'alexxiy.pivx'
            )
        ).toBe(false);
    });

    it('handles a u64 price beyond Number.MAX_SAFE_INTEGER without losing precision', () => {
        // Both are > 2^53, and differ only in the low bits: as Numbers they would be
        // the same value, so a Number-based implementation would hash them alike.
        const a = tamper({ price: '18446744073709551615' });
        const b = tamper({ price: '18446744073709551614' });
        expect(verifySmtProof(a, 'alexxiy.pivx')).toBe(false);
        expect(verifySmtProof(b, 'alexxiy.pivx')).toBe(false);
        // and neither throws
    });

    // Guard against silently regressing to the old dense tree. Every leaf used to
    // sit at depth 128 with a 128-entry proof; if that shape ever comes back, the
    // wallet is talking to a protocol that no longer exists.
    it('does not accept an old-format 128-level proof', () => {
        const dense = tamper({
            proof_depth: 128,
            merkle_proof: Array(128).fill(
                '0000000000000000000000000000000000000000000000000000000000000000'
            ),
        });
        expect(verifySmtProof(dense, 'alexxiy.pivx')).toBe(false);
        expect(LIVE_VECTOR.merkle_proof.length).not.toBe(128);
    });
});

describe('isPIVXName', () => {
    it('should return true for valid domain names with supported TLDs', () => {
        expect(isPIVXName('alex.pivx')).toBe(true);
        expect(isPIVXName('richard.secure')).toBe(true);
        expect(isPIVXName('hello-world.safe')).toBe(true);
        expect(isPIVXName('pivx-123.private')).toBe(true);
        expect(isPIVXName('ALEX.pivx')).toBe(true); // case-insensitive
    });

    it('should return false for invalid formats or unsupported TLDs', () => {
        expect(isPIVXName('alex.pivx2')).toBe(false);
        expect(isPIVXName('alex.pivx.name')).toBe(false);
        expect(isPIVXName('alex')).toBe(false);
        expect(isPIVXName('')).toBe(false);
        expect(isPIVXName(null)).toBe(false);
        expect(isPIVXName(undefined)).toBe(false);
    });

    it('should enforce hyphen restrictions (no leading, trailing, or consecutive)', () => {
        expect(isPIVXName('-alex.pivx')).toBe(false);
        expect(isPIVXName('alex-.pivx')).toBe(false);
        expect(isPIVXName('al--ex.pivx')).toBe(false);
        expect(isPIVXName('al-ex.pivx')).toBe(true);
    });

    it('should enforce length rules', () => {
        expect(isPIVXName('.pivx')).toBe(false);
        expect(isPIVXName('a.pivx')).toBe(true);
        expect(isPIVXName('a'.repeat(59) + '.pivx')).toBe(true); // total length = 64
        expect(isPIVXName('a'.repeat(60) + '.pivx')).toBe(false); // total length = 65
    });

    it('should reject invalid characters', () => {
        expect(isPIVXName('al_ex.pivx')).toBe(false);
        expect(isPIVXName('alex!.pivx')).toBe(false);
        expect(isPIVXName('alex space.pivx')).toBe(false);
    });
});

describe('isPIVXNameTLD', () => {
    it('should return true if name ends with a supported TLD', () => {
        expect(isPIVXNameTLD('alex.pivx')).toBe(true);
        expect(isPIVXNameTLD('test.secure')).toBe(true);
        expect(isPIVXNameTLD('check.safe')).toBe(true);
        expect(isPIVXNameTLD('secret.private')).toBe(true);
        expect(isPIVXNameTLD('upper.PIVX')).toBe(true);
    });

    it('should return false if name does not end with a supported TLD', () => {
        expect(isPIVXNameTLD('alex.pivx2')).toBe(false);
        expect(isPIVXNameTLD('alex.name')).toBe(false);
        expect(isPIVXNameTLD('alex')).toBe(false);
        expect(isPIVXNameTLD('')).toBe(false);
    });
});

describe('PIVXNameTLDs', () => {
    it('should contain the supported TLDs', () => {
        expect(PIVXNameTLDs).toEqual(['.pivx', '.secure', '.safe', '.private']);
    });
});

describe('EVM and Indexer Root Checking', () => {
    beforeEach(() => {
        vi.stubGlobal('fetch', vi.fn());
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('reads the chain root with currentRoot() straight from the browser', async () => {
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                result: '0x7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12',
            }),
        });

        const root = await fetchEVMRoot('https://rpc-url', '0xcontract');
        expect(root).toBe(
            '7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12'
        );
        expect(fetch).toHaveBeenCalledWith(
            'https://rpc-url',
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    method: 'eth_call',
                    params: [
                        {
                            to: '0xcontract',
                            data: '0xfdab463d', // currentRoot()
                        },
                        'latest',
                    ],
                    id: 1,
                }),
            })
        );
    });

    // getRoot, never info: info makes the indexer call the anchor contract server
    // side, so every user's request would go out through the indexer's single IP.
    it('reads the indexer root from /v1.0/getRoot, not /v1.0/info', async () => {
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                response:
                    '7FBE8F29F7278DB7A665DE4F1255927B40B648B43E55B34BB3E0405EDB5E7D12',
            }),
        });

        const root = await fetchIndexerRoot('https://indexer.pivx.name/');
        expect(root).toBe(
            '7fbe8f29f7278db7a665de4f1255927b40b648b43e55b34bb3e0405edb5e7d12'
        );
        expect(fetch).toHaveBeenCalledWith(
            'https://indexer.pivx.name/v1.0/getRoot'
        );
    });

    it('rejects a getRoot answer that is not a bare string', async () => {
        fetch.mockResolvedValueOnce({
            ok: true,
            // the old /v1.0/info shape must not be accepted here
            json: async () => ({ response: { indexer_smt_root: 'deadbeef' } }),
        });
        await expect(
            fetchIndexerRoot('https://indexer.pivx.name')
        ).rejects.toThrow(/Invalid response/);
    });

    it('asks the contract with isRootValid(bytes32) and reads a single bool', async () => {
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                result: '0x0000000000000000000000000000000000000000000000000000000000000001',
            }),
        });

        const valid = await verifyRootValidityOnContract(
            'https://rpc-url',
            '0xcontract',
            LIVE_VECTOR.smt_root
        );
        expect(valid).toBe(true);
        expect(fetch).toHaveBeenCalledWith(
            'https://rpc-url',
            expect.objectContaining({
                body: expect.stringContaining(
                    '0x30ef41b4' + LIVE_VECTOR.smt_root
                ),
            })
        );
    });

    it('returns false for a root the contract has never accepted', async () => {
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                result: '0x0000000000000000000000000000000000000000000000000000000000000000',
            }),
        });
        expect(
            await verifyRootValidityOnContract(
                'https://rpc-url',
                '0xcontract',
                LIVE_VECTOR.smt_root
            )
        ).toBe(false);
    });

    // rootHistory(bytes32) returns (uint32 blockHeight, bool isValid). Reading that
    // whole two-word return as one number answers "valid" for any root with a block
    // height recorded, whatever the flag says - which is why we call isRootValid.
    it('is not fooled by a repudiated root that still has a block height', async () => {
        fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                // isValid = false, even though a height is present in the struct
                result: '0x0000000000000000000000000000000000000000000000000000000000000000',
            }),
        });
        expect(
            await verifyRootValidityOnContract(
                'https://rpc-url',
                '0xcontract',
                LIVE_VECTOR.smt_root
            )
        ).toBe(false);
    });
});

describe('PiNS.vue Component', () => {
    beforeEach(async () => {
        vi.useFakeTimers();
        vi.stubGlobal('fetch', vi.fn());
        vi.spyOn(Database, 'getInstance').mockResolvedValue({
            getSettings: async () => ({
                nameResolvingApi: 'https://indexer.pivx.name',
                evmRpc: 'https://evm-rpc.pivx.name',
                evmContractAddress: '0xcontract',
            }),
        });
    });

    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
        vi.useRealTimers();
    });

    /**
     * Route mocks by URL and calldata rather than by call order: the component
     * starts the chain read and the resolve concurrently, so ordering is not a
     * stable thing to assert on.
     */
    function routeFetch({ resolve, indexerRoot, evmRoot, rootValid }) {
        fetch.mockImplementation(async (url, opts) => {
            const body = opts?.body ? JSON.parse(opts.body) : null;
            if (String(url).includes('/v1.0/resolve/')) {
                return { ok: true, json: async () => resolve };
            }
            if (String(url).includes('/v1.0/getRoot')) {
                return {
                    ok: true,
                    json: async () => ({ response: indexerRoot }),
                };
            }
            const data = body?.params?.[0]?.data ?? '';
            if (data.startsWith('0xfdab463d')) {
                return {
                    ok: true,
                    json: async () => ({ result: '0x' + evmRoot }),
                };
            }
            if (data.startsWith('0x30ef41b4')) {
                return {
                    ok: true,
                    json: async () => ({
                        result:
                            '0x' + (rootValid ? '1' : '0').padStart(64, '0'),
                    }),
                };
            }
            throw new Error('unexpected fetch: ' + url + ' ' + data);
        });
    }

    it('shows the security warning and stops polling when the indexer root is unknown to the contract', async () => {
        routeFetch({
            resolve: { error: { error_message: 'Domain not found' } },
            indexerRoot:
                '2222000000000000000000000000000000000000000000000000000000000000',
            evmRoot:
                '1111000000000000000000000000000000000000000000000000000000000000',
            rootValid: false,
        });

        const wrapper = mount(PiNS);
        await wrapper.vm.resolveAndVerify('alexxiy.pivx', 1, false, '');
        await vi.runOnlyPendingTimersAsync();

        expect(wrapper.vm.syncModalState).toBe('invalid_root');
        expect(wrapper.vm.syncModalTitle).toBe('Security Warning');
        // no send may be armed once the root is rejected
        expect(wrapper.vm.pendingSendParams).toBe(null);
    });

    it('never calls /v1.0/info', async () => {
        routeFetch({
            resolve: { response: LIVE_VECTOR },
            indexerRoot: LIVE_VECTOR.smt_root,
            evmRoot: LIVE_VECTOR.smt_root,
            rootValid: true,
        });

        const wrapper = mount(PiNS);
        await wrapper.vm.resolveAndVerify('alexxiy.pivx', 1, false, '');
        await vi.runOnlyPendingTimersAsync();

        const called = fetch.mock.calls.map((c) => String(c[0]));
        expect(called.some((u) => u.includes('/v1.0/info'))).toBe(false);
    });
});

describe('EVM RPC rotation', () => {
    const RPCS = ['https://rpc-a', 'https://rpc-b', 'https://rpc-c'];
    const OK = { result: '0x' + '1'.padStart(64, '0') };

    beforeEach(() => {
        vi.stubGlobal('fetch', vi.fn());
    });
    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    it('uses the first endpoint when it answers, and does not touch the others', async () => {
        fetch.mockResolvedValue({ ok: true, json: async () => OK });
        await evmCall(RPCS, '0xcontract', '0xfdab463d');
        expect(fetch).toHaveBeenCalledTimes(1);
        expect(fetch.mock.calls[0][0]).toBe('https://rpc-a');
    });

    it('rotates past a transport failure', async () => {
        fetch
            .mockRejectedValueOnce(
                new Error('NetworkError when attempting to fetch')
            )
            .mockResolvedValueOnce({ ok: true, json: async () => OK });
        const res = await evmCall(RPCS, '0xcontract', '0xfdab463d');
        expect(res).toBe(OK.result);
        expect(fetch.mock.calls.map((c) => c[0])).toEqual([
            'https://rpc-a',
            'https://rpc-b',
        ]);
    });

    it('rotates past HTTP failures such as 403 and 429', async () => {
        fetch
            .mockResolvedValueOnce({
                ok: false,
                status: 403,
                statusText: 'Forbidden',
            })
            .mockResolvedValueOnce({
                ok: false,
                status: 429,
                statusText: 'Too Many Requests',
            })
            .mockResolvedValueOnce({ ok: true, json: async () => OK });
        await expect(evmCall(RPCS, '0xcontract', '0xfdab463d')).resolves.toBe(
            OK.result
        );
        expect(fetch).toHaveBeenCalledTimes(3);
    });

    it('rotates past a JSON-RPC error object and an empty result', async () => {
        fetch
            .mockResolvedValueOnce({
                ok: true,
                json: async () => ({ error: { message: 'limit exceeded' } }),
            })
            .mockResolvedValueOnce({
                ok: true,
                json: async () => ({ result: '0x' }),
            })
            .mockResolvedValueOnce({ ok: true, json: async () => OK });
        await expect(evmCall(RPCS, '0xcontract', '0xfdab463d')).resolves.toBe(
            OK.result
        );
        expect(fetch).toHaveBeenCalledTimes(3);
    });

    it('throws only after every endpoint has failed, naming the last reason', async () => {
        fetch.mockRejectedValue(new Error('boom'));
        await expect(evmCall(RPCS, '0xcontract', '0xfdab463d')).rejects.toThrow(
            /All 3 EVM RPC endpoint\(s\) failed.*boom/
        );
        expect(fetch).toHaveBeenCalledTimes(3);
    });

    it('accepts a plain string for backwards compatibility', async () => {
        fetch.mockResolvedValue({ ok: true, json: async () => OK });
        await evmCall('https://rpc-only', '0xcontract', '0xfdab463d');
        expect(fetch.mock.calls[0][0]).toBe('https://rpc-only');
    });

    it('de-duplicates the endpoint list', async () => {
        fetch.mockRejectedValue(new Error('boom'));
        await expect(
            evmCall(['https://rpc-a', 'https://rpc-a'], '0xcontract', '0x00')
        ).rejects.toThrow(/All 1 EVM RPC endpoint/);
        expect(fetch).toHaveBeenCalledTimes(1);
    });

    // The critical one. A zero word is isRootValid answering "no". Rotating on it
    // would mean shopping around until some endpoint said yes - turning a security
    // verdict into a poll of whoever is reachable.
    it('does NOT rotate when the contract legitimately answers false', async () => {
        fetch.mockResolvedValue({
            ok: true,
            json: async () => ({ result: '0x' + '0'.repeat(64) }),
        });
        const valid = await verifyRootValidityOnContract(
            RPCS,
            '0xcontract',
            LIVE_VECTOR.smt_root
        );
        expect(valid).toBe(false);
        expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('rotation is transparent to fetchEVMRoot', async () => {
        fetch.mockRejectedValueOnce(new Error('down')).mockResolvedValueOnce({
            ok: true,
            json: async () => ({ result: '0x' + LIVE_VECTOR.smt_root }),
        });
        await expect(fetchEVMRoot(RPCS, '0xcontract')).resolves.toBe(
            LIVE_VECTOR.smt_root
        );
    });
});
