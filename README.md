# node-openssl
OpenSSL wrapper for NodeJS

Rewrite of [node-openssl-cert](https://github.com/lspiehler/node-openssl-cert)

Initial use case - generation of self-signed certificates.

```ts
import { NodeOpenSSL } from '@goosewobbler/node-openssl';

const openssl = new NodeOpenSSL();

(async () => {
  try {
    const { key, cmd } = await openssl.generateRSAPrivateKey(RSAKeyOptions);
    // key generated and stored on instance
    console.log('created private key: ', key);
    console.log('openssl command used: ', cmd);
  } catch(e) {
    console.error('error creating private key', e);
  }
  
  try {
    const { csr, cmd } = await openssl.generateCSR(csrOptions, certPassword);
    // instance key used to generate csr, csr stored on instance
    console.log('created csr: ', csr);
    console.log('openssl command used: ', cmd);
  } catch(e) {
    console.error('error creating csr', e);
  }
  
  try {
    const { crt, cmd } = await openssl.selfSignCSR(csrOptions, certPassword);
    // instance csr used for signing, cert stored on instance
    console.log('self signed cert: ', crt);
    console.log('openssl command used: ', cmd);
  } catch(e) {
    console.error('error self signing cert', e);
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
