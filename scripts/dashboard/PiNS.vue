<script setup>
import { ref } from 'vue';
import { Database } from '../database.js';
import { createAlert } from '../alerts/alert.js';
import { isShieldAddress } from '../misc.js';
import {
    fetchEVMRoot,
    fetchIndexerRoot,
    verifyRootValidityOnContract,
    verifySmtProof,
} from '../utils.pins.js';
import { ALERTS, translation, tr } from '../i18n.js';
import { cChainParams } from '../chain_params.js';
import { debugError, DebugTopics } from '../debug.js';

// Events we can emit
const emit = defineEmits(['send']);

// Reactive States
const showSyncModal = ref(false);
const syncModalState = ref('warning');
const syncModalTitle = ref('');
const syncModalText = ref('');
const syncModalConfirmText = ref('');
const syncModalCancelText = ref('');
const syncModalIsPolling = ref(false);
const pendingSendParams = ref(null);

let syncModalInterval = null;

/**
 * The EVM endpoints to try, best first.
 *
 * The user's chosen endpoint leads, then every other endpoint configured for the
 * same chain as a fallback. One rate limited or unreachable node must not take name
 * resolution down when spares are sitting in the chain params.
 */
function getEvmRpcList(strConfiguredRpc, nChainId) {
    const network = (cChainParams.current.EVMNetworks || []).find(
        (n) => n.chainId === nChainId
    );
    const arrSpares = network?.rpcs || [];
    return [strConfiguredRpc, ...arrSpares].filter(
        (url, i, arr) => url && arr.indexOf(url) === i
    );
}

async function resolveDomainName(apiEndpoint, domain) {
    const res = await fetch(
        `${apiEndpoint.replace(/\/$/, '')}/v1.0/resolve/${domain}`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({}),
        }
    );

    let json = null;
    try {
        json = await res.json();
    } catch (e) {
        // Not a JSON response
    }

    if (json && json.error) {
        const errMsg = json.error.error_message;
        if (errMsg === 'Domain not found') {
            return { isNotFound: true, resolveData: null };
        }
        throw new Error(errMsg);
    }

    if (!res.ok) {
        throw new Error(`Indexer responded with status ${res.status}`);
    }

    if (json && json.response) {
        return { isNotFound: false, resolveData: json.response };
    }

    throw new Error('Invalid response format from indexer');
}

async function getPivxNameRoots(
    apiEndpoint,
    strDomain,
    evmRpc,
    evmContractAddress
) {
    let resolveData = null;
    let isNotFound = false;
    let indexerRoot = null;

    // Kick the chain read off first so it overlaps the resolve instead of following
    // it. Attach a catch immediately: an unhandled rejection here would surface as a
    // global error before the await below ever sees it.
    const evmRootPromise = fetchEVMRoot(evmRpc, evmContractAddress);
    evmRootPromise.catch(() => {});

    try {
        const res = await resolveDomainName(apiEndpoint, strDomain);
        isNotFound = res.isNotFound;
        if (!isNotFound) {
            resolveData = res.resolveData;
            indexerRoot = resolveData.smt_root;
        }
    } catch (e) {
        if (e.message === 'Domain not found') {
            isNotFound = true;
        } else {
            throw e;
        }
    }

    const evmRoot = await evmRootPromise;

    // Only needed when the name is missing: with no resolve response there is no
    // root to compare, and we still have to tell "the indexer is behind" from
    // "this name genuinely does not exist".
    if (isNotFound) {
        indexerRoot = await fetchIndexerRoot(apiEndpoint);
    }

    const rootsMatch =
        !!evmRoot &&
        !!indexerRoot &&
        evmRoot.toLowerCase() === indexerRoot.toLowerCase();

    return { rootsMatch, evmRoot, indexerRoot, isNotFound, resolveData };
}

function verifyResolvedDetails(strDomain, resolveData) {
    if (!resolveData) return false;
    const resolvedAddress = resolveData.target_address;

    // The proof carries its own depth and terminal now, so completeness is checked
    // where the proof is parsed rather than by listing fields twice.
    if (
        !resolvedAddress ||
        !resolveData.owner_pubkey ||
        resolveData.price === undefined ||
        resolveData.nonce === undefined ||
        !resolveData.smt_root ||
        !Array.isArray(resolveData.merkle_proof) ||
        resolveData.proof_depth === undefined ||
        !resolveData.proof_terminal
    ) {
        createAlert(
            'warning',
            tr(ALERTS.PINS_INCOMPLETE_METADATA, [{ strDomain }]),
            5000
        );
        return false;
    }

    if (!verifySmtProof(resolveData, strDomain)) {
        createAlert('warning', ALERTS.PINS_INVALID_PROOF, 5000);
        return false;
    }

    if (!isShieldAddress(resolvedAddress)) {
        createAlert('warning', ALERTS.PINS_INVALID_SHIELD, 5000);
        return false;
    }

    if (resolveData.domain_name !== strDomain) {
        createAlert('warning', ALERTS.PINS_NAME_MISMATCH, 5000);
        return false;
    }

    return true;
}

async function verifyAndHandleRootValidity(
    evmRpc,
    evmContractAddress,
    indexerRoot
) {
    const isRootValid = await verifyRootValidityOnContract(
        evmRpc,
        evmContractAddress,
        indexerRoot
    );
    if (!isRootValid) {
        stopSyncModalPolling();
        pendingSendParams.value = null; // Clear to prevent any send
        showSyncModal.value = true;
        syncModalState.value = 'invalid_root';
        syncModalTitle.value = translation.pinsTitleSecurityWarning;
        syncModalText.value = translation.pinsTextSecurityWarning;
        syncModalCancelText.value = translation.pinsBtnClose;
        return false;
    }
    return true;
}

function handleCriticalError(e, isRetry = false) {
    const errMsg = e.message || String(e);
    const isNetworkError =
        errMsg.toLowerCase().includes('fetch') ||
        errMsg.toLowerCase().includes('networkerror') ||
        errMsg.toLowerCase().includes('timeout') ||
        errMsg.toLowerCase().includes('conn');
    if (!isNetworkError) {
        stopSyncModalPolling();
        pendingSendParams.value = null;
        showSyncModal.value = true;
        syncModalState.value = 'invalid_root';
        syncModalTitle.value = translation.pinsTitleIndexerError;
        syncModalText.value = tr(translation.pinsTextIndexerError, [
            { errMsg },
        ]);
        syncModalCancelText.value = translation.pinsBtnClose;
        return true;
    }

    if (isRetry) {
        createAlert('warning', tr(ALERTS.PINS_SYNC_FAILED, [{ errMsg }]), 3000);
    }
    return false;
}

function startSyncModalPolling(
    apiEndpoint,
    strDomain,
    evmRpcList,
    evmContractAddress
) {
    stopSyncModalPolling();
    syncModalIsPolling.value = true;

    syncModalInterval = setInterval(async () => {
        try {
            const { rootsMatch, indexerRoot, isNotFound, resolveData } =
                await getPivxNameRoots(
                    apiEndpoint,
                    strDomain,
                    evmRpcList,
                    evmContractAddress
                );

            // SECURITY CHECK: Verify if the indexer's root exists historically on the contract
            const isRootValid = await verifyAndHandleRootValidity(
                evmRpcList,
                evmContractAddress,
                indexerRoot
            );
            if (!isRootValid) return;

            if (rootsMatch) {
                stopSyncModalPolling();

                if (!isNotFound && resolveData && resolveData.target_address) {
                    if (pendingSendParams.value) {
                        pendingSendParams.value.address =
                            resolveData.target_address;
                        pendingSendParams.value.resolveData = resolveData;
                    }
                    syncModalState.value = 'synced';
                    syncModalTitle.value = translation.pinsTitleSynced;
                    syncModalText.value = translation.pinsTextSynced;
                    syncModalConfirmText.value = translation.pinsBtnSend;
                } else {
                    syncModalState.value = 'not_found_synced_error';
                    syncModalTitle.value = translation.pinsTitleNotFound;
                    syncModalText.value = translation.pinsTextNotFound;
                }
            }
        } catch (e) {
            debugError(
                DebugTopics.NET,
                'Sync modal background check error:',
                e
            );
            handleCriticalError(e);
        }
    }, 5000);
}

function stopSyncModalPolling() {
    syncModalIsPolling.value = false;
    if (syncModalInterval) {
        clearInterval(syncModalInterval);
        syncModalInterval = null;
    }
}

function closeSyncModal(confirm) {
    stopSyncModalPolling();
    showSyncModal.value = false;

    if (confirm && pendingSendParams.value) {
        const {
            address,
            amount,
            useShieldInputs,
            memo,
            originalDomain,
            resolveData,
        } = pendingSendParams.value;
        pendingSendParams.value = null;

        if (verifyResolvedDetails(originalDomain, resolveData)) {
            emit('send', { address, amount, useShieldInputs, memo });
        }
    } else {
        pendingSendParams.value = null;
    }
}

async function retrySyncModalResolution() {
    if (!showSyncModal.value || syncModalState.value !== 'not_found') return;

    const database = await Database.getInstance();
    const { nameResolvingApi, evmRpc, evmContractAddress, evmNetworkId } =
        await database.getSettings();
    const apiEndpoint = nameResolvingApi || 'https://indexer.pivx.name';
    const evmRpcList = getEvmRpcList(evmRpc, evmNetworkId);

    stopSyncModalPolling();

    const checkingAlert = createAlert(
        'info',
        translation.pinsCheckingSync,
        5000
    );
    try {
        const { rootsMatch, indexerRoot, isNotFound, resolveData } =
            await getPivxNameRoots(
                apiEndpoint,
                pendingSendParams.value.originalDomain,
                evmRpc,
                evmContractAddress
            );

        // SECURITY CHECK: Verify if the indexer's root exists historically on the contract
        const isRootValid = await verifyAndHandleRootValidity(
            evmRpcList,
            evmContractAddress,
            indexerRoot
        );
        if (!isRootValid) {
            if (checkingAlert) checkingAlert.close();
            return;
        }

        if (checkingAlert) checkingAlert.close();
        if (rootsMatch) {
            stopSyncModalPolling();
            if (!isNotFound && resolveData) {
                showSyncModal.value = false;
                if (
                    verifyResolvedDetails(
                        pendingSendParams.value.originalDomain,
                        resolveData
                    )
                ) {
                    emit('send', {
                        address: resolveData.target_address,
                        amount: pendingSendParams.value.amount,
                        useShieldInputs:
                            pendingSendParams.value.useShieldInputs,
                        memo: pendingSendParams.value.memo,
                    });
                }
            } else {
                showSyncModal.value = false;
                createAlert(
                    'warning',
                    tr(ALERTS.PINS_NOT_FOUND, [
                        { strDomain: pendingSendParams.value.originalDomain },
                    ]),
                    5000
                );
            }
        } else {
            createAlert('warning', translation.pinsSyncingWait, 3000);
            startSyncModalPolling(
                apiEndpoint,
                pendingSendParams.value.originalDomain,
                evmRpcList,
                evmContractAddress
            );
        }
    } catch (e) {
        if (checkingAlert) checkingAlert.close();
        handleCriticalError(e, true);
    }
}

async function resolveAndVerify(domain, amount, useShieldInputs, memo) {
    const strDomain = domain.toLowerCase();
    const resolvingAlert = createAlert(
        'info',
        tr(ALERTS.PINS_RESOLVING_DOMAIN, [{ strDomain }]),
        10000
    );

    try {
        const database = await Database.getInstance();
        const { nameResolvingApi, evmRpc, evmContractAddress, evmNetworkId } =
            await database.getSettings();
        const apiEndpoint = nameResolvingApi || 'https://indexer.pivx.name';
        // Pass the whole list from here on: every EVM call may rotate through it.
        const evmRpcList = getEvmRpcList(evmRpc, evmNetworkId);

        // 1. Fetch roots and resolved data
        const { rootsMatch, indexerRoot, isNotFound, resolveData } =
            await getPivxNameRoots(
                apiEndpoint,
                strDomain,
                evmRpcList,
                evmContractAddress
            );

        if (resolvingAlert) resolvingAlert.close();

        if (!rootsMatch) {
            // Verify if the indexer's root exists historically on the contract
            const isRootValid = await verifyAndHandleRootValidity(
                evmRpcList,
                evmContractAddress,
                indexerRoot
            );
            if (!isRootValid) return;

            // Roots mismatch! Keep send params for resumption
            pendingSendParams.value = {
                address: isNotFound ? '' : resolveData.target_address,
                amount,
                useShieldInputs,
                memo,
                originalDomain: strDomain,
                resolveData: isNotFound ? null : resolveData,
            };

            if (!isNotFound && resolveData && resolveData.target_address) {
                // State A: Domain Resolved (Roots Mismatch)
                showSyncModal.value = true;
                syncModalState.value = 'warning';
                syncModalTitle.value = translation.pinsTitleSyncDelay;
                syncModalText.value = translation.pinsTextSyncDelayResolved;
                syncModalConfirmText.value = translation.pinsBtnSendAnyway;
                syncModalCancelText.value = translation.pinsBtnCancel;

                startSyncModalPolling(
                    apiEndpoint,
                    strDomain,
                    evmRpcList,
                    evmContractAddress
                );
            } else {
                // State B: Domain Not Found (Roots Mismatch)
                showSyncModal.value = true;
                syncModalState.value = 'not_found';
                syncModalTitle.value = translation.pinsTitleSyncDelayNotFound;
                syncModalText.value = translation.pinsTextSyncDelayNotFound;
                syncModalCancelText.value = translation.pinsBtnCancel;

                startSyncModalPolling(
                    apiEndpoint,
                    strDomain,
                    evmRpcList,
                    evmContractAddress
                );
            }
            return;
        }

        // Roots matched! Check if resolved target was found
        if (isNotFound || !resolveData || !resolveData.target_address) {
            return createAlert(
                'warning',
                tr(ALERTS.PINS_NOT_FOUND, [{ strDomain }]),
                5000
            );
        }

        // Run cryptographic verification before sending!
        if (verifyResolvedDetails(strDomain, resolveData)) {
            emit('send', {
                address: resolveData.target_address,
                amount,
                useShieldInputs,
                memo,
            });
        }
    } catch (e) {
        if (resolvingAlert) resolvingAlert.close();
        debugError(DebugTopics.NET, 'Name service resolution error:', e);
        createAlert(
            'warning',
            tr(ALERTS.PINS_RESOLVE_FAILED, [{ errMsg: e.message || e }]),
            5000
        );
    }
}

// Expose public API
defineExpose({
    resolveAndVerify,
});
</script>

<template>
    <!-- Sync Warning Modal -->
    <div
        v-if="showSyncModal"
        class="modal fade show"
        style="
            display: block;
            background: rgba(0, 0, 0, 0.6);
            z-index: 1050;
            overflow-y: auto;
        "
        tabindex="-1"
        role="dialog"
    >
        <div class="modal-dialog modal-dialog-centered" role="document">
            <div
                class="modal-content text-center"
                style="
                    background: #1e1233;
                    color: #fff;
                    border: 1px solid #4e327a;
                    border-radius: 10px;
                    padding: 20px;
                "
            >
                <div
                    class="modal-header border-0 justify-content-center"
                    style="padding-bottom: 0"
                >
                    <h5
                        class="modal-title font-weight-bold"
                        style="color: #d5adff; font-size: 1.35rem"
                    >
                        {{ syncModalTitle }}
                    </h5>
                </div>
                <div
                    class="modal-body border-0"
                    style="
                        font-size: 0.95rem;
                        line-height: 1.5;
                        color: #e1d5f5;
                        padding-top: 15px;
                        padding-bottom: 15px;
                    "
                >
                    <p>{{ syncModalText }}</p>
                    <div
                        v-if="syncModalIsPolling"
                        class="mt-3 d-flex align-items-center justify-content-center"
                        style="color: #d5adff; font-size: 0.85rem; gap: 8px"
                    >
                        <span
                            class="spinner-border spinner-border-sm"
                            role="status"
                            aria-hidden="true"
                            style="
                                width: 1rem;
                                height: 1rem;
                                border-width: 0.15em;
                            "
                        ></span>
                        {{ translation.pinsPolling }}
                    </div>
                </div>
                <div
                    class="modal-footer border-0 justify-content-center"
                    style="padding-top: 0; display: flex; gap: 10px"
                >
                    <button
                        v-if="
                            syncModalState === 'warning' ||
                            syncModalState === 'synced'
                        "
                        type="button"
                        class="pivx-button-big"
                        style="width: 150px; margin: 0"
                        @click="closeSyncModal(true)"
                    >
                        {{ syncModalConfirmText }}
                    </button>
                    <button
                        v-if="syncModalState === 'not_found'"
                        type="button"
                        class="pivx-button-big"
                        style="width: 150px; margin: 0"
                        @click="retrySyncModalResolution"
                    >
                        {{ translation.pinsBtnRetry }}
                    </button>
                    <button
                        type="button"
                        class="pivx-button-big-cancel"
                        style="width: 150px; margin: 0"
                        @click="closeSyncModal(false)"
                    >
                        {{ syncModalCancelText }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>
