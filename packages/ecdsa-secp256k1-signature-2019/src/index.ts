import { EcdsaSecp256k1VerificationKey2019 } from '@blockcerts/ecdsa-secp256k1-verification-key-2019';
import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';
import { context } from './context';

const SUITE_CONTEXT_URL = 'https://ns.did.ai/suites/secp256k1-2019/v1';
const W3ID_SUITE_CONTEXT_URL = 'https://w3id.org/security/suites/secp256k1-2019/v1';
const VC_V1_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1';
const VC_V2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';

const includesContext = ({ document, contextUrl }: { document: Record<string, unknown>; contextUrl: string[] }) => {
  const context = document['@context'];

  if (Array.isArray(context)) {
    return contextUrl.some(url => context.includes(url));
  }

  return contextUrl.includes(context as string);
};

const includesCompatibleContext = ({
                                     document
                                   }) => {
  const hasSecp256k12019 = includesContext({
    document,
    contextUrl: [SUITE_CONTEXT_URL, W3ID_SUITE_CONTEXT_URL]
  });
  const hasCredV1 = includesContext({
    document,
    contextUrl: [VC_V1_CONTEXT_URL]
  });
  const hasCredV2 = includesContext({
    document,
    contextUrl: [VC_V2_CONTEXT_URL]
  });
  const hasSecV2 = includesContext({
    document,
    contextUrl: ['https://w3id.org/security/v2']
  });
  if (hasSecp256k12019 && hasCredV1) {
    console.warn('Warning: The secp256k1-2019/v1 and credentials/v1 contexts are incompatible.');
    console.warn('For VCs using EcdsaSecp256k1Signature2019 suite, using the credentials/v1 context is sufficient.');
    return false;
  }
  if (!hasSecp256k12019 && hasCredV2) {
    console.warn('This library does not (yet) follow the Data Integrity Proof format.');
    console.warn('When using the credentials/v2 context, consumers need to specify the secp256k1-2019/v1 context.');
    return false;
  }
  if (hasSecp256k12019 && hasSecV2) {
    console.warn('Warning: The secp256k1-2019/v1 and security/v2 contexts are incompatible.');
    console.warn('For VCs using EcdsaSecp256k1Signature2019 suite, using the security/v2 context is sufficient.');
    return false;
  }

  return hasSecp256k12019 || hasCredV1 || hasSecV2;
};

type EcdsaSecp256k1Signature2019Options = {
  key?: EcdsaSecp256k1VerificationKey2019;
  signer?: { sign: ({ verifyData, proof }: { verifyData: Uint8Array; proof: Record<string, any> }) => any; id: string };
  verifier?: { verify: ({ data, signature }: { data: Uint8Array, signature: any }) => any; id: string };
  proof?: Record<string, unknown>;
  date?: Date | string;
  useNativeCanonize?: boolean;
}

export class EcdsaSecp256k1Signature2019 extends jsigs.suites.LinkedDataSignature {
  private requiredKeyType: string;

  constructor(options: EcdsaSecp256k1Signature2019Options = {}) {
    super({
      type: 'EcdsaSecp256k1Signature2019',
      LDKeyClass: EcdsaSecp256k1VerificationKey2019,
      contextUrl: SUITE_CONTEXT_URL,
      ...options
    });

    this.requiredKeyType = 'EcdsaSecp256k1VerificationKey2019';
  }

  async sign({ verifyData, proof }: { verifyData: Uint8Array; proof: Record<string, any> }) {
    // @ts-expect-error signer comes from LinkedDataSignature class but no definition is available
    if (!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.');
    }

    // @ts-expect-error signer comes from LinkedDataSignature class but no definition is available
    const jws = await this.signer.sign({ data: verifyData });

    return {
      ...proof,
      jws
    };
  }

  async verifySignature({
    verifyData,
    verificationMethod,
    proof
  }: {
    verifyData: Uint8Array
    verificationMethod: Record<string, unknown>
    proof: Record<string, unknown>
  }) {
    const { jws } = proof;

    if (!(jws && typeof jws === 'string')) {
      throw new TypeError('The proof does not include a valid "jws" property.');
    }

    // @ts-expect-error verifier comes from LinkedDataSignature class but no definition is available
    let { verifier } = this;
    if (!verifier) {
      // @ts-expect-error LDKeyClass comes from LinkedDataSignature class but no definition is available
      const key = await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier();
    }

    return verifier.verify({ data: verifyData, signature: jws });
  }

  async assertVerificationMethod({ verificationMethod }: { verificationMethod: Record<string, unknown> }) {
    if (!includesCompatibleContext({ document: verificationMethod })) {
      // @ts-expect-error contextUrl comes from LinkedDataSignature class but no definition is available
      throw new TypeError(`The verification method (key) must contain "${this.contextUrl}".`);
    }

    if (!jsonld.hasValue(verificationMethod, 'type', this.requiredKeyType)) {
      throw new Error(`Invalid key type. Key type must be "${this.requiredKeyType}".`);
    }

    if (verificationMethod.revoked !== undefined) {
      throw new Error('The verification method has been revoked.');
    }
  }

  async getVerificationMethod({
    proof,
    documentLoader
  }: {
    proof: { verificationMethod: string | { id: string } | undefined }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
    documentLoader: Function
  }) {
    // @ts-expect-error key comes from LinkedDataSignature class but no definition is available
    if (this.key) {
      // @ts-expect-error key comes from LinkedDataSignature class but no definition is available
      return this.key.export({ publicKey: true });
    }

    const verificationMethod = typeof proof.verificationMethod === 'object' ? proof.verificationMethod.id : proof.verificationMethod;

    if (!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.');
    }

    const framed = await jsonld.frame(
      verificationMethod,
      {
        // @ts-expect-error contextUrl comes from LinkedDataSignature class but no definition is available
        '@context': this.contextUrl,
        '@embed': '@always',
        id: verificationMethod
      },
      { documentLoader, compactToRelative: false }
    );

    if (!framed) {
      throw new Error(`Verification method ${verificationMethod} not found.`);
    }

    if (framed.revoked !== undefined) {
      throw new Error('The verification method has been revoked.');
    }

    await this.assertVerificationMethod({ verificationMethod: framed });

    return framed;
  }

  async matchProof({
    proof,
    document,
    purpose,
    documentLoader,
    expansionMap
  }: {
    proof: Record<string, any>
    document: Record<string, any>
    purpose: Record<string, any>
    // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
    documentLoader: Function
    // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
    expansionMap: Function
  }) {
    if (!includesCompatibleContext({ document })) {
      return false;
    }
    if (
      !(await super.matchProof({
        proof,
        document,
        purpose,
        documentLoader,
        expansionMap
      }))
    ) {
      return false;
    }
    // @ts-expect-error key comes from LinkedDataSignature class but no definition is available
    if (!this.key) {
      // no key specified, so assume this suite matches and it can be retrieved
      return true;
    }

    const { verificationMethod } = proof;

    const verificationMethodId: string = typeof verificationMethod === 'object' ? verificationMethod.id : verificationMethod;
    return this.isVerificationMethodMatchingKeyId(verificationMethodId);
  }

  ensureSuiteContext({ document, addSuiteContext }: { document: Record<string, unknown>; addSuiteContext?: boolean }) {
    if (includesCompatibleContext({ document }) && !includesContext({ document, contextUrl: [VC_V2_CONTEXT_URL] })) {
      return;
    }

    super.ensureSuiteContext({ document, addSuiteContext });
  }

  private isVerificationMethodMatchingKeyId(verificationMethod: string): boolean {
    // @ts-expect-error key comes from LinkedDataSignature class but no definition is available
    return verificationMethod === this.key.id || verificationMethod === `${this.key.controller}${this.key.id}`;
  }
}

// @ts-expect-error defining it at class does not seem to work, moving on
EcdsaSecp256k1Signature2019.CONTEXT_URL = SUITE_CONTEXT_URL;
// @ts-expect-error defining it at class does not seem to work, moving on
EcdsaSecp256k1Signature2019.CONTEXT = context;
