# node-openssl

OpenSSL wrapper for NodeJS

Rewrite of [node-openssl-cert](https://github.com/lspiehler/node-openssl-cert)

Initial use case - generation of self-signed certificates.

```ts
import { NodeOpenSSL } from '@goosewobbler/node-openssl';

const openssl = new NodeOpenSSL();

(async () => {
  try {
    // creating private key
    const { key, cmd } = await openssl.generatePrivateKey(RSAKeyOptions);
    csrOpts.key = key;

    // create CSR from key - should also generate pkey if not specified
    const csr = await openssl.generateCSR(csrOpts);
    const { key } = csr;
    // openssl req -config cnf/ssl.cnf -new -out csr/{acme.domain}-csr.pem

    // create self-signed root CA - should also generate pkey if not specified
    const ca = await openssl.generateRootCA(caOpts);
    const { crt, key, cmd } = ca;
    // openssl req -config cnf/ca.cnf -x509 -new -days 1095 -out ca/rootCA-crt.pem

    // sign CSR with root CA
    const { crt, key, csr, cmd } = await ca.signCSR(csr);
    // openssl x509 -req -in csr/{acme.domain}-csr.pem -CA ca/rootCA-crt.pem -CAkey ca/rootCA-key.pem -CAcreateserial -out {acme.domain}-crt.pem -days 365 -sha512 -extfile cnf/ssl.cnf -extensions v3_req

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

/* old interface - self signed with CA */
openssl.generateRSAPrivateKey(RSAKeyOptions, (err, cakey, cmd) => {
  if (err) {
    reject(err);
  }
  console.log(cmd);
  openssl.generateCSR(CACSROptions, cakey, certPassword, (err, csr, cmd) => {
    if (err) {
      reject(err);
    }

    csroptions.days = 240;
    openssl.selfSignCSR(csr, CACSROptions, cakey, certPassword, (err, cacrt, cmd) => {
      if (err) {
        reject(err);
      }

      console.log(cmd.command);
      console.log(cacrt);
      console.log(cmd.files.config);
      const userDataPath = app.getPath('userData');
      const CACertFilePath = path.join(userDataPath, 'frame_ca_crt.pem');
      // const keyFilePath = path.join(userDataPath, 'frame_key.pem')

      fs.writeFile(CACertFilePath, cacrt, (certFileError) => {
        console.log('certFileError', certFileError);
      });

      // fs.writeFile(keyFilePath, key, (keyFileError) => {
      //   console.log('keyFileError', keyFileError)
      // })

      openssl.generateRSAPrivateKey(RSAKeyOptions, (err, key, cmd) => {
        if (err) {
          reject(err);
        }
        console.log(cmd);
        openssl.generateCSR(csroptions, key, certPassword, (err, csr, cmd) => {
          if (err) {
            reject(err);
          }

          csroptions.days = 240;
          openssl.CASignCSR(csr, csroptions, false, cacrt, cakey, certPassword, (err, crt, cmd) => {
            if (err) {
              reject(err);
            }

            console.log(cmd.command);
            console.log(crt);
            console.log(cmd.files.config);
            const userDataPath = app.getPath('userData');
            const certFilePath = path.join(userDataPath, 'frame_crt.pem');
            const keyFilePath = path.join(userDataPath, 'frame_key.pem');

            fs.writeFile(certFilePath, crt, (certFileError) => {
              console.log('certFileError', certFileError);
            });

            fs.writeFile(keyFilePath, key, (keyFileError) => {
              console.log('keyFileError', keyFileError);
            });

            resolve({ certFilePath, keyFilePath, certPassword, CACertFilePath });
          });
        });
      });
    });
  });
});
```
