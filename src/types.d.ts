export type PrivateKeyResult = {
  key: string;
  cmd: string;
};

export type GeneratePrivateKeyParams = {
  format?: string;
  algorithm?: string;
  encrypted?: boolean;
  encryptOpts?: {
    password: string;
    cipher: string;
  };
  paramFile?: string;
  pkeyOpts?: { [Key: string]: string | number };
};

export type GenerateCSRParams = {
  keyFile: string;
  keyPassword?: string;
  newKey?: string;
  messageDigest?: string;
  outputFile?: string;
  outputKeyFile?: string;
  distinguishedName?: {
    [key: string]: string;
  };
  altNames?: {
    [key: string]: string;
  };
};

export type GenerateRootCAParams = {
  outputFile: string;
  keyFile: string;
  distinguishedName?: {
    [key: string]: string;
  };
  expiryDays?: number;
};

export type SignCSRParams = {
  outputFile?: string;
  csrFile: string;
  caCrtFile: string;
  caKeyFile: string;
  configFile: string;
  expiryDays?: number;
};

export interface Output {
  cmd: string;
  config: string;
  files: {
    [key: string]: string;
  };
}

export interface CSRResult extends Output {
  csr: string;
}

export interface CAResult extends Output {
  ca: string;
  signCSR: ({ csrFile, outputFile }: Partial<SignCSRParams>) => Promise<SignedCertResult>;
}

export interface SignedCertResult extends Output {
  crt: string;
}

export type CommandResult = {
  command: string;
  stdOut: string;
  stdErr: string;
  exitCode: number;
};
