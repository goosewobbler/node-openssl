# node-openssl
OpenSSL wrapper for NodeJS

Rewrite of [node-openssl-cert](https://github.com/lspiehler/node-openssl-cert)

Initial use case - generation of self-signed certificates.

```ts
import { NodeOpenSSL } from '@goosewobbler/node-openssl';

const openssl = new NodeOpenSSL();  // might not need a class

async generateCSR() {
  try {
    const result = await openssl.generateRSAPrivateKey(RSAKeyOptions);
    console.log('created private key: ', result.key);
    console.log('openssl command used: ', result.cmd);
    
    try {
      const csrObj = await result.generateCSR(csrOptions, certPassword);
      console.log('created csr: ', csrObj.csr);
      console.log('openssl command used: ', csrObj.cmd);
      return csrObj;
    } catch(e) {
      console.error('error creating csr', e);
    }
  } catch(e) {
    console.error('error creating private key', e);
  }
}

(async () => {
  try {
    // creating private key separately
    const { key, cmd } = await openssl.generateRSAPrivateKey(RSAKeyOptions);  // do we need 'RSA' here? check openSSL docs
    csrOpts.key = key;
  
    // creates private key using options if key is not specified
    const csr = await openssl.generateCSR(csrOpts); // key specified
    const caCSR = await openssl.generateCSR(caOpts, RSAKeyOptions); // key not specified
    
    const ca = await caCSR.selfSign();
    const { crt, key, csr, cmd } = await ca.signCSR(csr);
    
    console.log(cmd.command);
    console.log(crt);
    console.log(cmd.files.config);
    const userDataPath = app.getPath('userData');
    const certFilePath = path.join(userDataPath, 'frame_crt.pem');
    const keyFilePath = path.join(userDataPath, 'frame_key.pem');
    const caFilePath = path.join(userDataPath, 'frame_ca.pem');

    // maybe move file creation into the wrapper
    fs.writeFile(certFilePath, crt, (certFileError) => {
      console.log('certFileError', certFileError);
    });
    fs.writeFile(keyFilePath, key, (keyFileError) => {
      console.log('keyFileError', keyFileError);
    });
    fs.writeFile(caFilePath, ca.crt, (caFileError) => {
      console.log('caFileError', caFileError);
    });
  } catch(e) {
    console.error('error creating cert', e);
  }
  
})()



/* old interface - self signed with CA (likely misconfigured) */
openssl.generateRSAPrivateKey(RSAKeyOptions, (err, cakey, cmd) => {
      if (err) {
        reject(err)
      }
      console.log(cmd)
      openssl.generateCSR(CACSROptions, cakey, certPassword, (err, csr, cmd) => {
        if (err) {
          reject(err)
        }

        csroptions.days = 240
        openssl.selfSignCSR(csr, CACSROptions, cakey, certPassword, (err, cacrt, cmd) => {
          if (err) {
            reject(err)
          }

          console.log(cmd.command)
          console.log(cacrt)
          console.log(cmd.files.config)
          const userDataPath = app.getPath('userData')
          const CACertFilePath = path.join(userDataPath, 'frame_ca_crt.pem')
          // const keyFilePath = path.join(userDataPath, 'frame_key.pem')

          fs.writeFile(CACertFilePath, cacrt, (certFileError) => {
            console.log('certFileError', certFileError)
          })

          // fs.writeFile(keyFilePath, key, (keyFileError) => {
          //   console.log('keyFileError', keyFileError)
          // })

          openssl.generateRSAPrivateKey(RSAKeyOptions, (err, key, cmd) => {
            if (err) {
              reject(err)
            }
            console.log(cmd)
            openssl.generateCSR(csroptions, key, certPassword, (err, csr, cmd) => {
              if (err) {
                reject(err)
              }

              csroptions.days = 240
              openssl.CASignCSR(csr, csroptions, false, cacrt, cakey, certPassword, (err, crt, cmd) => {
                if (err) {
                  reject(err)
                }

                console.log(cmd.command)
                console.log(crt)
                console.log(cmd.files.config)
                const userDataPath = app.getPath('userData')
                const certFilePath = path.join(userDataPath, 'frame_crt.pem')
                const keyFilePath = path.join(userDataPath, 'frame_key.pem')

                fs.writeFile(certFilePath, crt, (certFileError) => {
                  console.log('certFileError', certFileError)
                })

                fs.writeFile(keyFilePath, key, (keyFileError) => {
                  console.log('keyFileError', keyFileError)
                })

                resolve({ certFilePath, keyFilePath, certPassword, CACertFilePath })
              })
            })
          })
        })
      })
    })
```
