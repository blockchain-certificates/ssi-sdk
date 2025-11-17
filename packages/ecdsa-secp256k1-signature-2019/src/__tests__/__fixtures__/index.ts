import credentialsContextDoc from './contexts/credentials-v1.json';
import didContextDoc from './contexts/did-v0.11.json';
import secp256k12019ContextDoc from './contexts/secp256k1-2019-v1.json';
import schemaContextDoc from './contexts/schema.json';
import didDoc from './didDocument.json';
import keyPair from './keyPair.json';
import keyPairRelativeId from './keyPairRelativePathId.json';

const contextMap: { [url: string]: Record<string, unknown> } = {
  'https://www.w3.org/2018/credentials/v1': credentialsContextDoc,
  'https://w3id.org/did/v0.11': didContextDoc,
  'https://ns.did.ai/suites/secp256k1-2019/v1': secp256k12019ContextDoc,
  'http://schema.org': schemaContextDoc
};

const didDocMap: { [url: string]: Record<string, unknown> } = {
  'did:example:signer': didDoc
};

export const documentLoader = (url: string) => {
  const withoutFragment = url.split('#')[0];
  const document = (withoutFragment.startsWith('did:') ? didDocMap : contextMap)[withoutFragment] || null;

  if (document === null) console.log({ url, withoutFragment });

  return {
    document,
    documentUrl: url
  };
};

export { didDoc };

export const document = {
  '@context': ['http://schema.org', 'https://ns.did.ai/suites/secp256k1-2019/v1'],
  '@type': 'Person',
  name: 'Bob Belcher'
};

export const publicKeyPair = keyPair.public;
export const privateKeyPair = keyPair.private;

export const publicKeyPairRelativePath = keyPairRelativeId.public;
export const privateKeyPairRelativePath = keyPairRelativeId.private;
