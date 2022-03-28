# node-openssl

OpenSSL wrapper for NodeJS

Minimal rewrite of [node-openssl-cert](https://github.com/lspiehler/node-openssl-cert).

Initial use case - generation of self-signed certificates.

### FAQ

_Why?_

`node-openssl-cert` covers a wide spectrum of openssl functionality but has some serious limitations. A similar approach was taken but utilising a more light-weight and cleaner promise-based interface.

_Does it do everything that `node-openssl-cert` does?_

Not yet, the initial feature set is geared around creating self-signed certs with scope for expansion to a more comprehensive wrapper. If you're desparate for an openssl feature to be included feel free to submit a PR.

_What version of OpenSSL is required?_

3.0

### Example usage

```ts
import { NodeOpenSSL } from '@goosewobbler/node-openssl';

// path defaults to 'openssl'
const openssl = new NodeOpenSSL('/path/to/openssl_bin');

(async () => {
  try {
    // creating private key
    const pKey = await openssl.generatePrivateKey();
    const { key, cmd, file } = pKey;

    // create CSR from key - should also generate pkey if not specified
    const csrOpts = {
      subjectAltName: {
        'DNS.1': '{acme.domain}',
        'IP.1': '{192.168.x.x}',
        'IP.2': '0.0.0.0',
        'IP.3': '127.0.0.1',
      },
      distinguishedName: {
        C: 'Test Country',
        ST: 'Test State or Province',
        L: 'Test Locality',
        O: 'Organization Name',
        OU: 'Organizational Unit Name',
        CN: 'Common Name',
        emailAddress: 'test@email.address',
      },
      keyFile: 'test-csr.key',
      outputFile: 'test-csr.pem',
    };
    const csr = await pKey.generateCSR(csrOpts); // syntactic sugar
    const csr = await openssl.generateCSR({ ...csrOpts, keyFile: file });
    const { key, cmd, file, keyfile } = csr;
    // original (key generated):
    // openssl req -config cnf/ssl.cnf -new -out csr/{acme.domain}-csr.pem
    // key provided (self signing only):
    // openssl req -config cnf/ssl.cnf -new -key ssl/{acme.domain}.key -out csr/{acme.domain}-csr.pem

    // create self-signed root CA - should also generate pkey if not specified
    const caOpts = {
      distinguishedName: {
        C: 'Test Country',
        ST: 'Test State or Province',
        L: 'Test Locality',
        O: 'Organization Name',
        OU: 'Organizational Unit Name',
        CN: 'Common Name',
        emailAddress: 'test@email.address',
      },
      expiryDays: 1095,
      keyFile: 'test-ca.key',
      outputFile: 'test-ca.pem',
    };
    const ca = await openssl.generateRootCA(caOpts);
    const { crt, key, cmd } = ca;
    // openssl req -config cnf/ca.cnf -x509 -new -days 1095 -out ca/rootCA-crt.pem

    // sign CSR with root CA
    const caCsrOpts = {
      outputFile: 'test-crt.pem',
      expiryDays: 1095,
    };
    const { crt, key, csr, cmd } = await ca.signCSR({ ...caCsrOpts, csrFile: csr.file }); // syntactic sugar
    const { crt, key, csr, cmd } = await openssl.signCSR({
      ...caCsrOpts,
      csrFile: csr.file,
      caFile: ca.crt,
      caKeyFile: ca.key,
    });
    // original:
    // openssl x509 -req -in csr/{acme.domain}-csr.pem -CA ca/rootCA-crt.pem -CAkey ca/rootCA-key.pem -CAcreateserial -out {acme.domain}-crt.pem -days 365 -sha512 -extfile cnf/ssl.cnf -extensions v3_req
    // v2 - req:
    // openssl req -in csr/{acme.domain}-csr.pem -out {acme.domain}-crt.pem -CA ca/rootCA-crt.pem -CAkey ca/rootCA-key.pem -days 365 -copy_extensions copy

    console.log(cmd);
    console.log(crt);
    const userDataPath = app.getPath('userData');
    const certFilePath = path.join(userDataPath, 'frame_crt.pem');
    const keyFilePath = path.join(userDataPath, 'frame_key.pem');
    const caFilePath = path.join(userDataPath, 'frame_ca.pem');

    fs.writeFile(certFilePath, crt, (certFileError) => {
      console.log('certFileError', certFileError);
    });
    fs.writeFile(keyFilePath, key, (keyFileError) => {
      console.log('keyFileError', keyFileError);
    });
    fs.writeFile(caFilePath, ca.crt, (caFileError) => {
      console.log('caFileError', caFileError);
    });
  } catch (e) {
    console.error('error creating cert', e);
  }
})();
```
