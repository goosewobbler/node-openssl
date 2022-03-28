type ConfigBlockData = {
  [key: string]: string | number;
};

type ConfigParams = {
  distinguishedName?: {
    [key: string]: string;
  };
};

function generateLine(key: string, value: string | number) {
  if (!value) {
    return '';
  }
  const keyStringLength = 23;
  const paddingLength = keyStringLength - key.length;
  return `${key.padEnd(paddingLength)} = ${value}\n`;
}

function generateBlock(blockTitle: string, blockData: ConfigBlockData | undefined) {
  if (!blockData) {
    return '';
  }
  let block = `[ ${blockTitle} ]\n`; // \r\n?
  block += Object.keys(blockData).map((key) => generateLine(key, blockData[key]));
  return block;
}

export const generateConfig = ({ distinguishedName }: ConfigParams) => {
  const generateBlockReference = (key: string, blockName: string, blockData: ConfigBlockData | undefined) =>
    blockData ? { [key]: blockName } : {};
  const config = `
       ${generateBlock('req', {
         prompt: 'no',
         default_bits: 4096, // configurable, default 4096 (cmd override -newkey rsa:4096, default 2048)
         default_md: 'sha512', // configurable, default sha512, validate digest supported by dgst (cmd override -digest, default sha256)
         default_keyfile: '{acme.domain}-key.pem', // configurable, ignored if not specified (cmd override -keyout)
         string_mask: 'utf8only',
         utf8: 'yes',
         ...generateBlockReference('distinguished_name', 'req_distinguished_name', distinguishedName),
       })}
        req_extensions 			= v3_req

        ${generateBlock('req_distinguished_name', distinguishedName)}
        
        [ v3_req ]
        basicConstraints        = CA:FALSE /* hard coded, different values for ssl & ca */
        keyUsage                = nonRepudiation, digitalSignature, keyEncipherment /* hard coded - ssl only */
        subjectAltName          = @alt_names /* hard coded - ssl only */
        
        [alt_names]
        DNS.1                   = {acme.domain}
        IP.1                    = {192.168.x.x}
        IP.2                    = 0.0.0.0
        IP.3                    = 127.0.0.1 /* configurable as alt_names block - ssl only */
        `;
  return config;
};
