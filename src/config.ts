type ConfigBlockData = {
  [key: string]: string | number;
};

type ConfigParams = {
  messageDigest: string;
  extensionsType: string;
  extensionsBlockName: string;
  distinguishedName?: {
    [key: string]: string;
  };
  extensionsBlockData?: {
    [key: string]: string;
  };
  altNames?: {
    [key: string]: string;
  };
};

function generateLine(key: string, value: string | number) {
  if (!value) {
    return '';
  }
  return `${key.padEnd(23)} = ${value}\n`;
}

function generateBlock(blockTitle: string, blockData: ConfigBlockData | undefined) {
  if (!blockData) {
    return '';
  }
  const blockContents = Object.keys(blockData)
    .map((key) => generateLine(key, blockData[key]))
    .join('');
  return `[ ${blockTitle} ]\n${blockContents}\n`;
}

export const generateConfig = ({
  messageDigest,
  distinguishedName,
  extensionsType,
  extensionsBlockName,
  extensionsBlockData,
  altNames,
}: ConfigParams) => {
  const generateBlockReference = (key: string, blockName: string, blockData: ConfigBlockData | undefined) =>
    blockData ? { [key]: `${blockName}` } : {};
  return `
${generateBlock('req', {
  prompt: 'no',
  default_bits: 4096, // configurable, default 4096 (cmd override -newkey rsa:4096, default 2048)
  default_md: messageDigest, // configurable, default sha512, validate digest supported by dgst (cmd override -digest, default sha256)
  // default_keyfile: '{acme.domain}-key.pem', // configurable, ignored if not specified (cmd override -keyout)
  string_mask: 'utf8only',
  utf8: 'yes',
  ...generateBlockReference('distinguished_name', 'req_distinguished_name', distinguishedName),
  ...generateBlockReference(`${extensionsType}_extensions`, extensionsBlockName, extensionsBlockData),
})}
${generateBlock('req_distinguished_name', distinguishedName)}
${generateBlock(extensionsBlockName, {
  ...extensionsBlockData,
  ...generateBlockReference('subjectAltName', '@alt_names', altNames),
})}
${generateBlock('alt_names', altNames)}
`;
};
