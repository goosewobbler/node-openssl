import { spawn } from 'child_process';
import { cwd } from 'process';
import * as tmp from 'tmp-promise';
import { writeFile } from 'fs/promises';
import { generateConfig } from './config';
import {
  CAResult,
  CommandResult,
  CSRResult,
  GenerateCSRParams,
  GeneratePrivateKeyParams,
  GenerateRootCAParams,
  Output,
  PrivateKeyResult,
  SignCSRParams,
  SignedCertResult,
} from './types';

export class NodeOpenSSL {
  private openSSLPath;

  private supportedCiphers?: string[];

  private openSSLVersionInfo?: string;

  public commandLog: CommandResult[] = [];

  constructor(openSSLPath = 'openssl') {
    this.openSSLPath = openSSLPath;
  }

  public async getOpenSSLVersion(): Promise<string | undefined> {
    const parseVersionInfo = (): string | undefined => {
      const versionStringMatches = (this.openSSLVersionInfo as string).match(/OpenSSL\s([0-9]\.[0-9]\.[0-9][a-z])/);
      if (versionStringMatches && versionStringMatches.length) {
        return versionStringMatches[0].replace('OpenSSL ', '');
      }
      return undefined;
    };

    if (!this.openSSLVersionInfo) {
      const { stdOut } = await this.runCommand('version', ['-a']);
      this.openSSLVersionInfo = stdOut;
    }

    return Promise.resolve(parseVersionInfo());
  }

  private async runCommand(command: string, rawParams: string[] | string[][], stdIn?: string): Promise<CommandResult> {
    const stdOutBuffer: Uint8Array[] = [];
    const stdErrBuffer: Uint8Array[] = [];
    const params = rawParams.flat();
    let exitCode: number;
    let exited = false;

    console.log('running command', command, params);

    return new Promise((resolve, reject) => {
      const handleExit = () => {
        const out = {
          command: `${this.openSSLPath} ${command} ${params.join(' ')}`,
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
        const openssl = spawn(this.openSSLPath, [command, ...params]);

        if (stdIn) {
          openssl.stdin.write(stdIn);
          openssl.stdin.end();
        }

        openssl.stdout.on('data', (data: Uint8Array) => {
          stdOutBuffer.push(data);
          if (exited && exitCode === 0) {
            handleExit();
          }
        });

        openssl.on('error', (err: Error) => {
          console.log(err);
          return reject(err);
        });

        openssl.stderr.on('data', (data: Uint8Array) => {
          stdErrBuffer.push(data);
          if (exited && exitCode !== 0) {
            handleExit();
          }
        });

        openssl.on('exit', (code: number) => {
          exited = true;
          exitCode = code;
          const stdOutReceived = stdOutBuffer.length > 0 || params.includes('-out');
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
    console.log('getting supported ciphers');
    const result = await this.runCommand('enc', ['-list']);
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

    const params = ['-outform', 'PEM'];
    let stdIn;

    if (paramFile) {
      params.push('-paramFile', paramFile);
    } else {
      // algorithm is mutually exclusive with paramfile
      if (!validAlgorithms.includes(algorithm)) {
        throw new Error(`Invalid algorithm: ${algorithm}`);
      }
      params.push('-algorithm', algorithm);

      Object.keys(pkeyOpts).forEach((key) => {
        params.push('-pkeyopt', `${key}:${pkeyOpts[key]}`);
      });
    }

    if (encrypted) {
      const validCiphers = this.supportedCiphers ?? (await this.getSupportedCiphers());
      const validOpenSSLPassphrase = /^(pass|env|file|fd):.*/;
      const { cipher, password } = encryptOpts;
      let passphrase = 'stdin';

      if (!validCiphers.includes(`-${cipher}`)) {
        throw new Error(`Invalid cipher: ${cipher}`);
      }

      if (validOpenSSLPassphrase.test(password)) {
        passphrase = password;
      } else {
        stdIn = password;
      }
      params.push('-pass', `"${passphrase}"`, `-${cipher}`);
    }

    const { command: cmd, stdOut: key } = await this.runCommand('genpkey', params, stdIn);

    return { key, cmd };
  }

  public async generateCSR(
    {
      keyFile,
      keyPassword,
      newKey = 'rsa:4096',
      messageDigest = 'sha512',
      outputFile = 'csr.pem',
      outputKeyFile,
      distinguishedName,
      altNames,
    }: GenerateCSRParams = { keyFile: `${cwd()}/csr.key` },
  ): Promise<CSRResult> {
    const params = [
      ['-new', '-noenc'],
      ['-out', `${outputFile}`],
    ];

    if (outputKeyFile) {
      // create new private key, output to keyFile
      params.push(['-newkey', newKey], ['-keyout', outputKeyFile]);

      // TODO: passout for creating encrypted key
    } else {
      // TODO: verify keyFile exists / is readable?
      // use existing private key
      params.push(['-key', keyFile]);

      if (keyPassword) {
        params.push(['-passin', keyPassword]);
      }
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
        extensionsType: 'req',
        extensionsBlockName: 'v3_req',
        extensionsBlockData: reqExtensions,
        altNames,
      });
      await writeFile(configFilePath, config);
    } catch (e) {
      throw new Error(`Error writing config file: ${e as string}`);
    }

    params.push(['-config', `${configFilePath}`]);

    const { command: cmd, stdOut: csr } = await this.runCommand('req', params);

    return { csr, cmd, config, files: { key: keyFile, csr: outputFile } };
  }

  public async generateRootCA({
    distinguishedName,
    outputFile,
    keyFile,
    expiryDays = 365,
  }: GenerateRootCAParams): Promise<CAResult> {
    const params = [
      ['-x509', '-new', '-noenc'],
      ['-out', outputFile],
      ['-keyout', keyFile],
      ['-days', expiryDays.toString()],
    ];
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
        extensionsType: 'x509',
        extensionsBlockName: 'v3_ca',
        extensionsBlockData: reqExtensions,
      });
      await writeFile(configFile, config);
    } catch (e) {
      throw new Error(`Error writing config file: ${e as string}`);
    }

    params.push(['-config', configFile]);

    const { command: cmd } = await this.runCommand('req', params);
    const caCrtFile = outputFile;

    return {
      cmd,
      ca: outputFile,
      config,
      files: {},
      signCSR: async (params: Partial<SignCSRParams>): Promise<SignedCertResult> =>
        this.signCSR({ ...params, caCrtFile, caKeyFile: keyFile, configFile } as SignCSRParams),
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
    const params = [
      ['-in', csrFile],
      ['-days', expiryDays.toString()],
      ['-CA', caCrtFile],
      ['-CAkey', caKeyFile],
      ['-config', configFile],
      ['-copy_extensions', 'copy'],
    ];

    const files = {
      csr: csrFile,
      caCrt: caCrtFile,
      caKey: caKeyFile,
    } as Output['files'];

    if (outputFile) {
      params.push(['-out', outputFile]);
      files.crt = outputFile;
    }

    const { command: cmd, stdOut: crt } = await this.runCommand('req', params);

    return {
      cmd,
      crt,
      config: '',
      files,
    };
  }
}
