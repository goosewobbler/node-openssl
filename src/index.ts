import { spawn } from 'child_process';

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
  keyFile?: string;
  keySize?: number;
  messageDigest?: string;
  outputFile?: string;
  distinguishedName?: string;
  subjectAltName?: string;
};

type CSRResult = {
  key: string;
  csr: string;
  cmd: string;
};

type CommandResult = {
  command: string;
  stdOut: string;
  stdErr: string;
  exitCode: number;
};

// TODO: verify usage / requirement and clean up or remove
function normalizeCommand(command: string) {
  let cmd = command.split(' ');
  let outcmd = [];
  let cmdbuffer = [];
  for (let i = 0; i <= cmd.length - 1; i++) {
    if (cmd[i].charAt(cmd[i].length - 1) == '\\') {
      cmdbuffer.push(cmd[i]);
    } else {
      if (cmdbuffer.length > 0) {
        outcmd.push(cmdbuffer.join(' ') + ' ' + cmd[i]);
        cmdbuffer.length = 0;
      } else {
        outcmd.push(cmd[i]);
      }
    }
  }
  return outcmd;
}

export class NodeOpenSSL {
  private openSSLPath;
  private supportedCiphers?: string[];
  public commandLog: CommandResult[] = [];

  constructor(openSSLPath = 'openssl') {
    this.openSSLPath = openSSLPath;
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

    let cmdBits = ['genpkey -outform PEM'];
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

  public async generateCSR({
    keyFile,
    keySize = 4096,
    messageDigest = 'sha512',
    outputFile = 'csr.pem',
    distinguishedName,
    subjectAltName,
  }: GenerateCSRParams = {}): Promise<CSRResult> {
    let cmdBits = [`openssl req -new -noenc -out ${outputFile}`];

    //TODO: generate conf file

    if (configFile) {
      cmdBits.push(`-config ${configFile}`);
    }

    const { command: cmd, stdOut: csr } = await this.runCommand({ cmd: cmdBits.join(' ') });

    //TODO: read (created or supplied) keyFile

    return { key, csr, cmd };
  }

  public async generateRootCA() {
    return {
      signCSR: () => {},
    };
  }
}
