import { Api, JsonRpc } from "eosjs";
interface NonceVerificationParams {
    waxAddress: string;
    proof: {
        serializedTransaction: Uint8Array;
        signatures: string[];
    };
    nonce: string;
}
export declare class InvalidProofError extends Error {
    message: string;
}
export declare class WaxAuthServer {
    endpoint: JsonRpc;
    api: Api;
    chainId: string;
    actionName: string;
    nonceParamName: string;
    constructor(rpcUrl?: string, chainId?: string, actionName?: string, nonceParamName?: string);
    generateNonce(): string;
    verifyNonce({ waxAddress, proof, nonce }: NonceVerificationParams): Promise<boolean>;
}
export {};
