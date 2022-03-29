import { NodeOpenSSL } from '../../src/index';

// path defaults to 'openssl'
const openssl = new NodeOpenSSL('/usr/local/opt/openssl@3/bin/openssl');

async function generateSelfSignedCert() {
  const distinguishedName = {
    C: 'XX',
    ST: 'Test State or Province',
    L: 'Test Locality',
    O: 'Organization Name',
    OU: 'Organizational Unit Name',
    CN: 'Common Name',
    emailAddress: 'test@email.address',
  };
  const csrOpts = {
    subjectAltName: {
      'DNS.1': '{acme.domain}',
      'IP.1': '{192.168.x.x}',
      'IP.2': '0.0.0.0',
      'IP.3': '127.0.0.1',
    },
    distinguishedName,
    keyFile: 'test-csr.key',
    outputFile: 'test-csr.pem',
  };
  const { files } = await openssl.generateCSR(csrOpts);
  const caOpts = {
    distinguishedName,
    expiryDays: 1095,
    keyFile: 'test-ca.key',
    outputFile: 'test-ca.pem',
  };
  const ca = await openssl.generateRootCA(caOpts);
  const caCsrOpts = {
    outputFile: 'test-crt.pem',
    expiryDays: 1095,
  };
  return ca.signCSR({ ...caCsrOpts, csrFile: files.csr });
}

it('should generate a valid certificate', async () => {
  await generateSelfSignedCert();
  // key: test-csr.key
  // ca: test-ca.pem
  // crt: test-crt.pem
});
