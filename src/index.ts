import { spawn } from 'child_process';
import { cwd } from 'process';
import * as tmp from 'tmp-promise';
import { writeFile } from 'fs/promises';
import { generateConfig } from './config';

type PrivateKeyResult = {
  key: string;
  cmd: string;
};

type GeneratePrivateKeyParams = {
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

type GenerateCSRParams = {
  keyFile: string;
  newKey?: string;
  messageDigest?: string;
  outputFile?: string;
  distinguishedName?: {
    [key: string]: string;
  };
  altNames?: {
    [key: string]: string;
  };
};

type GenerateRootCAParams = {
  outputFile: string;
  keyFile: string;
  distinguishedName?: {
    [key: string]: string;
  };
  expiryDays?: number;
};

type SignCSRParams = {
  outputFile?: string;
  csrFile: string;
  caCrtFile: string;
  caKeyFile: string;
  configFile: string;
  expiryDays?: number;
};

interface Output {
  cmd: string;
  config: string;
  files: {
    [key: string]: string;
  };
}

interface CSRResult extends Output {
  csr: string;
}

interface CAResult extends Output {
  ca: string;
  signCSR: ({ csrFile, outputFile }: Partial<SignCSRParams>) => Promise<SignedCertResult>;
}

interface SignedCertResult extends Output {
  crt: string;
}

type CommandResult = {
  command: string;
  stdOut: string;
  stdErr: string;
  exitCode: number;
};

// TODO: verify usage / requirement and clean up or remove
function normalizeCommand(command: string) {
  const cmd = command.split(' ');
  const outcmd = [];
  const cmdbuffer = [];
  for (let i = 0; i <= cmd.length - 1; i++) {
    if (cmd[i].charAt(cmd[i].length - 1) == '\\') {
      cmdbuffer.push(cmd[i]);
    } else if (cmdbuffer.length > 0) {
        outcmd.push(`${cmdbuffer.join(' ')  } ${  cmd[i]}`);
        cmdbuffer.length = 0;
      } else {
        outcmd.push(cmd[i]);
      }
  }
  return outcmd;
}

export class NodeOpenSSL {
  private openSSLPath;

  private supportedCiphers?: string[];

  public openSSLVersionInfo?: string;

  public commandLog: CommandResult[] = [];

  constructor(openSSLPath = 'openssl') {
    this.openSSLPath = openSSLPath;
    (async () => {
      const { stdOut } = await this.runCommand({ cmd: 'version -a' });
      this.openSSLVersionInfo = stdOut;
    })();
  }

  private async runCommand({ cmd, stdIn }: { cmd: string; stdIn?: string }): Promise<CommandResult> {
    const stdOutBuffer: Uint8Array[] = [];
    const stdErrBuffer: Uint8Array[] = [];
    let exitCode: number;
    let exited = false;

    return new Promise((resolve, reject) => {
      const handleExit = () => {
        const out = {
          command: `${this.openSSLPath} ${cmd}`,
          stdOut: Buffer.concat(stdOutBuffer).toString(),
          stdErr: Buffer.concat(stdErrBuffer).toString(),
          exitCode,
        };
        this.commandLog.push(out);
        if (exitCode !== 0) {
          reject(out);
        } else {
          resolve(out);
        }
      };

      try {
        const openssl = spawn(this.openSSLPath, normalizeCommand(cmd));

        if (stdIn) {
          openssl.stdin.write(stdIn);
          openssl.stdin.end();
        }

        openssl.stdout.on('data', (data) => {
          stdOutBuffer.push(data);
          if (exited && exitCode === 0) {
            handleExit();
          }
        });

        openssl.on('error', (err: Error) => {
          console.log(err);
          return reject(err);
        });

        openssl.stderr.on('data', (data) => {
          stdErrBuffer.push(data);
          if (exited && exitCode !== 0) {
            handleExit();
          }
        });

        openssl.on('exit', (code) => {
          exited = true;
          exitCode = code as number;
          const stdOutReceived = stdOutBuffer.length > 0 || cmd.includes(' -out ');
          const stdErrReceived = stdErrBuffer.length > 0;
          if ((stdOutReceived && exitCode === 0) || (stdErrReceived && exitCode !== 0)) {
            handleExit();
          }
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  public async getSupportedCiphers(): Promise<string[]> {
    const result = await this.runCommand({ cmd: 'enc -list' });
    const ciphers = result.stdOut.match(
      /-[a-zA-Z0-9]{2,11}(-[a-zA-Z0-9]{2,11})?(-[a-zA-Z0-9]{2,11})?(-[a-zA-Z0-9]{2,11})?/g,
    );
    if (!ciphers) {
      throw new Error('Could not retrieve list of supported ciphers from openssl');
    }
    this.supportedCiphers = ciphers;
    return ciphers;
  }

  public async generatePrivateKey({
    algorithm = 'RSA',
    encrypted = false,
    encryptOpts = { cipher: 'des3', password: 'test123' },
    paramFile,
    pkeyOpts = {},
  }: GeneratePrivateKeyParams = {}): Promise<PrivateKeyResult> {
    const validAlgorithms = ['RSA', 'RSA-PSS', 'EC', 'X25519', 'X448', 'ED25519', 'ED448'];

    const cmdBits = ['genpkey -outform PEM'];
    let stdIn;

    if (paramFile) {
      cmdBits.push(`-paramfile ${paramFile}`);
    } else {
      // algorithm is mutually exclusive with paramfile
      if (!validAlgorithms.includes(algorithm)) {
        throw new Error(`Invalid algorithm: ${algorithm}`);
      }
      cmdBits.push(`-algorithm ${algorithm}`);

      Object.keys(pkeyOpts).forEach((key) => {
        cmdBits.push(`-pkeyopt ${key}:${pkeyOpts[key]}`);
      });
    }

    if (encrypted) {
      const validCiphers = this.supportedCiphers ?? (await this.getSupportedCiphers());
      const validOpenSSLPassphrase = /^(pass|env|file|fd):.*/;
      const { cipher, password } = encryptOpts;
      let passphrase = 'stdin';

      if (!validCiphers.includes(cipher)) {
        throw new Error(`Invalid cipher: ${cipher}`);
      }

      if (validOpenSSLPassphrase.test(password)) {
        passphrase = password;
      } else {
        stdIn = password;
      }
      cmdBits.push(`-pass ${passphrase} -${cipher}`);
    }

    const { command: cmd, stdOut: key } = await this.runCommand({ cmd: cmdBits.join(' '), stdIn });

    return { key, cmd };
  }

  public async generateCSR(
    {
      keyFile,
      newKey = 'rsa:4096',
      messageDigest = 'sha512',
      outputFile = 'csr.pem',
      distinguishedName,
      altNames,
    }: GenerateCSRParams = { keyFile: `${cwd}/csr.key` },
  ): Promise<CSRResult> {
    const cmdBits = [`req -new -noenc -out ${outputFile}`];

    if (newKey) {
      // create new private key, output to keyFile
      cmdBits.push(`-newkey ${newKey} -keyout ${keyFile}`);
    } else {
      // use existing private key
      cmdBits.push(`-key ${keyFile}`);
    }

    const reqExtensions = {
      basicConstraints: 'CA:FALSE',
      keyUsage: 'nonRepudiation, digitalSignature, keyEncipherment',
    };

    let configFilePath;
    let config;
    try {
      const tmpFile = await tmp.file({ mode: 0o644, prefix: 'csr-', postfix: '.cnf' });
      configFilePath = tmpFile.path;
      config = generateConfig({
        messageDigest,
        distinguishedName,
        reqExtensionBlockName: 'v3_req',
        reqExtensions,
        altNames,
      });
      await writeFile(configFilePath, config);
    } catch (e) {
      throw new Error(`Error writing config file: ${e}`);
    }

    cmdBits.push(`-config ${configFilePath}`);

    const { command: cmd, stdOut: csr } = await this.runCommand({ cmd: cmdBits.join(' ') });

    return { csr, cmd, config, files: { key: keyFile, csr: outputFile } };
  }

  public async generateRootCA({
    distinguishedName,
    outputFile,
    keyFile,
    expiryDays,
  }: GenerateRootCAParams): Promise<CAResult> {
    const cmdBits = [`req -x509 -new -noenc -out ${outputFile} -keyout ${keyFile} -days ${expiryDays}`];
    // openssl req -config cnf/ca.cnf -x509 -new -days 1095 -out ca/rootCA-crt.pem

    const reqExtensions = {
      basicConstraints: 'critical,CA:TRUE,pathlen:0',
      subjectKeyIdentifier: 'hash',
      authorityKeyIdentifier: 'keyid:always,issuer',
    };

    let configFile: string;
    let config: string;
    try {
      const tmpFile = await tmp.file({ mode: 0o644, prefix: 'ca-', postfix: '.cnf' });
      configFile = tmpFile.path;
      config = generateConfig({
        messageDigest: 'sha512',
        distinguishedName,
        reqExtensionBlockName: 'v3_ca',
        reqExtensions,
      });
      await writeFile(configFile, config);
    } catch (e) {
      throw new Error(`Error writing config file: ${e}`);
    }

    cmdBits.push(`-config ${configFile}`);

    const { command: cmd } = await this.runCommand({ cmd: cmdBits.join(' ') });
    const caCrtFile = outputFile;

    return {
      cmd,
      ca: outputFile,
      config,
      files: {},
      signCSR: async ({ csrFile, outputFile }: Partial<SignCSRParams>): Promise<SignedCertResult> => this.signCSR({ csrFile, caCrtFile, caKeyFile: keyFile, outputFile, configFile } as SignCSRParams),
    };
  }

  public async signCSR({
    outputFile,
    expiryDays = 365,
    csrFile,
    caCrtFile,
    caKeyFile,
    configFile,
  }: SignCSRParams): Promise<SignedCertResult> {
    // openssl req -in csr/{acme.domain}-csr.pem -out {acme.domain}-crt.pem -CA ca/rootCA-crt.pem -CAkey ca/rootCA-key.pem -days 365 -copy_extensions copy
    const cmdBits = [
      `req -in ${csrFile} -days ${expiryDays} -CA ${caCrtFile} -CAkey ${caKeyFile} -config ${configFile} -copy_extensions copy`,
    ];

    const files = {
      csr: csrFile,
      caCrt: caCrtFile,
      caKey: caKeyFile,
    } as Output['files'];

    if (outputFile) {
      cmdBits.push(`-out ${outputFile}`);
      files.crt = outputFile;
    }

    const { command: cmd, stdOut: crt } = await this.runCommand({ cmd: cmdBits.join(' ') });

    return {
      cmd,
      crt,
      config: '',
      files,
    };
  }
}
