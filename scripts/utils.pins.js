import { Buffer } from 'buffer';
import { sha256 } from '@noble/hashes/sha256';

export function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

export const PIVXNameTLDs = ['.pivx', '.secure', '.safe', '.private'];

/**
 * Domain separation tags for the compact Sparse Merkle Tree.
 *
 * In the old dense tree every leaf sat at depth 128, so a leaf hash could never
 * appear at an internal position and these tags were only defence in depth. In the
 * compact tree a leaf legitimately sits at an internal position, so the tags are the
 * only thing distinguishing "a leaf is here" from "a subtree is here". They are
 * mandatory - dropping either one makes forged proofs possible.
 */
const LEAF_TAG = 0x00;
const NODE_TAG = 0x01;

/** An empty subtree is 32 zero bytes at every depth; there is no per-height ladder. */
const EMPTY_NODE = Buffer.alloc(32);

/** A key is 128 bits, so a path can never be longer than that. */
export const MAX_PROOF_DEPTH = 128;

/**
 * Check if a domain string ends with one of the supported PIVX TLDs
 * @param {string} strDomain
 * @returns {boolean}
 */
export function isPIVXNameTLD(strDomain) {
    if (!strDomain) return false;
    const lower = strDomain.toLowerCase();
    return PIVXNameTLDs.some((tld) => lower.endsWith(tld));
}

/**
 * Check if a string is a valid PIVX domain name (PiNS format)
 * @param {string} strDomain
 * @returns {boolean}
 */
export function isPIVXName(strDomain) {
    if (!strDomain) return false;
    const lower = strDomain.toLowerCase();

    // Find matching TLD
    const matchedTld = PIVXNameTLDs.find((tld) => lower.endsWith(tld));
    if (!matchedTld) return false;

    // Extract label
    const label = lower.substring(0, lower.length - matchedTld.length);

    // Total domain length must be <= 64 characters
    if (strDomain.length > 64) return false;

    // Label length must be > 0
    if (label.length < 1) return false;

    // Check characters: lowercase alphanumeric + hyphens
    const regex = /^[a-z0-9-]+$/;
    if (!regex.test(label)) return false;

    // Hyphens: No leading, trailing, or consecutive
    if (label.startsWith('-') || label.endsWith('-') || label.includes('--'))
        return false;

    return true;
}

/**
 * The 128-bit tree key a domain's path is read from.
 * @param {string} strDomain - MUST already be lowercased.
 * @returns {Uint8Array} the first 16 bytes of SHA256(domain)
 */
function domainKey(strDomain) {
    return sha256(new TextEncoder().encode(strDomain)).slice(0, 16);
}

/**
 * Bit `i` of the path, most significant bit first within each byte.
 * Bit 0 selects the left child.
 */
function keyBit(key, i) {
    return (key[i >> 3] >> (7 - (i & 7))) & 1;
}

/** u64 little-endian. Takes a BigInt so a price near 2^53 cannot lose precision. */
function u64LE(value) {
    const buf = Buffer.alloc(8);
    let v = BigInt(value);
    if (v < 0n || v > 0xffffffffffffffffn) {
        throw new Error('value out of u64 range');
    }
    for (let i = 0; i < 8; i++) {
        buf[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return buf;
}

/**
 * hash_leaf - must match pins_core::hash_leaf byte for byte.
 * @param {string} strDomain - lowercased domain
 * @param {string} strPubkeyHex - 32-byte owner pubkey, hex
 * @param {string} strTargetAddress - the shield address the name points at
 * @param {bigint|number|string} price
 * @param {bigint|number|string} nonce
 */
function hashLeaf(strDomain, strPubkeyHex, strTargetAddress, price, nonce) {
    return sha256(
        Buffer.concat([
            Buffer.from([LEAF_TAG]),
            Buffer.from(strDomain, 'utf8'),
            Buffer.from(strPubkeyHex, 'hex'),
            Buffer.from(strTargetAddress, 'utf8'),
            u64LE(price),
            u64LE(nonce),
        ])
    );
}

/** hash_node - must match pins_core::hash_node byte for byte. */
function hashNode(left, right) {
    return sha256(
        Buffer.concat([
            Buffer.from([NODE_TAG]),
            Buffer.from(left),
            Buffer.from(right),
        ])
    );
}

/**
 * Fold a proof from its terminal depth up to the root.
 *
 * `siblings` is ordered deepest first, so step `i` consumes the sibling at depth
 * `d - i` and turns on path bit `d - 1 - i`.
 */
function fold(key, startHash, arrSiblings) {
    let h = startHash;
    for (let i = 0; i < arrSiblings.length; i++) {
        const sibling = arrSiblings[i];
        h = keyBit(key, arrSiblings.length - 1 - i)
            ? hashNode(sibling, h)
            : hashNode(h, sibling);
    }
    return h;
}

/**
 * Verify a compact SMT inclusion proof for a resolved name.
 *
 * The proof is variable depth: `proof_depth` levels of siblings, with a terminal
 * saying what sits at the bottom. A resolve always answers with `Occupied` - the
 * name's own leaf - because the indexer returns "Domain not found" rather than an
 * absence proof, so `Vacant` and `Blocked` are rejected here as malformed.
 *
 * The depth is self authenticating: folding the wrong number of times yields a
 * different root, so a shortened or padded proof cannot reproduce `expectedRoot`.
 *
 * @param {object} objResolve - the `response` object from /v1.0/resolve
 * @param {string} strDomain - the name the user asked for (any case)
 * @returns {boolean} true only if the proof folds to the root the indexer published
 */
export function verifySmtProof(objResolve, strDomain) {
    if (!objResolve || !strDomain) return false;

    const {
        target_address: strTargetAddress,
        owner_pubkey: strOwnerPubkey,
        price,
        nonce,
        smt_root: strExpectedRoot,
        merkle_proof: arrProof,
        proof_depth: nDepth,
        proof_terminal: strTerminal,
    } = objResolve;

    if (
        !strTargetAddress ||
        !strOwnerPubkey ||
        price === undefined ||
        price === null ||
        nonce === undefined ||
        nonce === null ||
        !strExpectedRoot ||
        !Array.isArray(arrProof)
    ) {
        return false;
    }

    // A resolve is an inclusion proof or it is nothing.
    if (strTerminal !== 'Occupied') return false;

    // The sibling count IS the depth; a mismatch means a malformed or doctored proof.
    if (!Number.isInteger(nDepth) || nDepth !== arrProof.length) return false;
    if (nDepth > MAX_PROOF_DEPTH) return false;

    // One normalisation, used for both the key and the leaf preimage. Deriving them
    // from differently cased strings would break every proof.
    const strLower = strDomain.toLowerCase();

    let current;
    let arrSiblings;
    try {
        current = hashLeaf(
            strLower,
            strOwnerPubkey,
            strTargetAddress,
            price,
            nonce
        );
        arrSiblings = arrProof.map((s) => {
            const buf = Buffer.from(s, 'hex');
            if (buf.length !== 32) throw new Error('bad sibling length');
            return buf;
        });
    } catch (e) {
        return false;
    }

    const root = fold(domainKey(strLower), current, arrSiblings);
    return bytesToHex(root) === strExpectedRoot.toLowerCase();
}

/**
 * The root of an empty registry, for callers that need to recognise it.
 * Exported so tests and callers do not re-derive the constant.
 */
export const EMPTY_ROOT = bytesToHex(EMPTY_NODE);

/**
 * Perform one eth_call, trying each endpoint in turn until one answers.
 *
 * Every contract read is done client side on purpose: the indexer would otherwise
 * have to make this call for every user from one IP and wear the rate limit alone.
 * That only helps if a single unlucky endpoint cannot take the feature down for a
 * user, hence the rotation - public BSC endpoints rate limit on per-second
 * concurrency and some answer 403 outright.
 *
 * Rotation happens on transport errors, non-2xx replies, JSON-RPC error objects and
 * empty results. It deliberately does NOT happen on a successful call that returns
 * a zero word: `0x000…0` is a legitimate `false` from isRootValid, and retrying
 * other endpoints until one disagreed would turn "this root is invalid" into "keep
 * asking until somebody says yes".
 *
 * @param {string|string[]} rpcUrls - endpoints to try, in order
 * @param {string} contractAddress
 * @param {string} strData - abi-encoded calldata, 0x-prefixed
 * @returns {Promise<string>} the raw result word(s), 0x-prefixed
 */
export async function evmCall(rpcUrls, contractAddress, strData) {
    const arrRpcs = (Array.isArray(rpcUrls) ? rpcUrls : [rpcUrls]).filter(
        (url, i, arr) => url && arr.indexOf(url) === i
    );
    if (!arrRpcs.length) throw new Error('No EVM RPC endpoint configured');

    const payload = {
        jsonrpc: '2.0',
        method: 'eth_call',
        params: [
            {
                to: contractAddress,
                data: strData,
            },
            'latest',
        ],
        id: 1,
    };

    let lastError = null;
    for (const rpcUrl of arrRpcs) {
        try {
            const response = await fetch(rpcUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });

            if (!response.ok) {
                throw new Error(
                    `Failed to fetch from EVM RPC: ${response.status} ${response.statusText}`
                );
            }

            const data = await response.json();
            if (data.error) {
                throw new Error(`EVM RPC error: ${data.error.message}`);
            }

            const hexResult = data.result;
            if (!hexResult || hexResult === '0x') {
                throw new Error('EVM RPC returned empty result');
            }
            return hexResult;
        } catch (e) {
            // Keep the reason, try the next endpoint. Only if every one of them
            // fails does the caller hear about it.
            lastError = e;
        }
    }

    throw new Error(
        `All ${arrRpcs.length} EVM RPC endpoint(s) failed, last error: ${
            lastError?.message || lastError
        }`
    );
}

/**
 * Read the anchor contract's current root, straight from the user's browser.
 *
 * @param {string|string[]} rpcUrls
 * @param {string} contractAddress
 * @returns {Promise<string>} the root, lowercase hex, no 0x prefix
 */
export async function fetchEVMRoot(rpcUrls, contractAddress) {
    // 0xfdab463d is the selector for currentRoot()
    const hexResult = await evmCall(rpcUrls, contractAddress, '0xfdab463d');
    return hexResult.replace(/^0x/, '').toLowerCase();
}

/**
 * Read the indexer's own SMT root.
 *
 * Deliberately /v1.0/getRoot and not /v1.0/info: `info` makes the indexer call the
 * anchor contract server side to fill in `anchored_smt_root`, funnelling every
 * user's request through the indexer's IP. `getRoot` is served from local storage
 * with no EVM call at all, and the chain side is read by the browser instead.
 *
 * @param {string} apiEndpoint
 * @returns {Promise<string>} the root, lowercase hex, no 0x prefix
 */
export async function fetchIndexerRoot(apiEndpoint) {
    const res = await fetch(`${apiEndpoint.replace(/\/$/, '')}/v1.0/getRoot`);
    if (!res.ok) {
        throw new Error(`Indexer getRoot responded with status ${res.status}`);
    }
    const data = await res.json();
    // getRoot answers with the root as a bare string, not an object.
    if (!data || typeof data.response !== 'string' || !data.response) {
        throw new Error('Invalid response from indexer getRoot');
    }
    return data.response.toLowerCase();
}

/**
 * Ask the anchor contract whether a root is one it accepted and still stands behind.
 *
 * The indexer can only ever be BEHIND the chain, never ahead: it applies commands up
 * to a checkpoint and refuses to commit unless its own computed root equals that
 * checkpoint's root, and checkpoints come from the contract. So every root an honest
 * indexer can serve is in the contract's history, including the genesis root, which
 * the constructor seeds.
 *
 * A `false` here therefore means the root was never accepted, or was repudiated by a
 * rollback - both of which make any proof folding to it worthless. There is no benign
 * reading of it.
 *
 * Uses isRootValid(bytes32) rather than the public rootHistory(bytes32) getter: that
 * getter now returns a (uint32 blockHeight, bool isValid) struct, so a caller reading
 * the whole return as one number would answer "valid" for any root with a recorded
 * block height, whatever the flag says.
 *
 * @param {string|string[]} rpcUrls
 * @param {string} contractAddress
 * @param {string} smtRoot
 * @returns {Promise<boolean>}
 */
export async function verifyRootValidityOnContract(
    rpcUrls,
    contractAddress,
    smtRoot
) {
    if (!smtRoot) return false;
    // 30ef41b4 is the selector for isRootValid(bytes32)
    const cleanRoot = smtRoot.replace(/^0x/, '').toLowerCase();
    const hexResult = await evmCall(
        rpcUrls,
        contractAddress,
        `0x30ef41b4${cleanRoot.padStart(64, '0')}`
    );

    // isRootValid returns a single ABI word: 0 for false, 1 for true. A zero here is
    // a real answer from a healthy endpoint, never a reason to ask a different one.
    return BigInt(hexResult) !== 0n;
}
