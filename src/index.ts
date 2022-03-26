import { spawn } from 'child_process';

type PrivateKeyResult = {
  key: string;
  cmd: string;
};

type PrivateKeyParams = {
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

type CommandResult = {
  command: string;
  stdOut: string;
  stdErr: string;
  exitCode: number;
};

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

  constructor(openSSLPath = 'openssl') {
    this.openSSLPath = openSSLPath;
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
    format = 'PKCS8',
  }: PrivateKeyParams = {}): Promise<PrivateKeyResult> {
    const validFormats = ['PKCS8', 'PKCS1'];
    const validAlgorithms = ['RSA', 'RSA-PSS', 'EC', 'X25519', 'X448', 'ED25519', 'ED448'];
    const validCiphers = this.supportedCiphers ?? (await this.getSupportedCiphers());
    const validOpenSSLPassphrase = /^(pass|env|file|fd):.*/;

    if (!validFormats.includes(format)) {
      throw new Error(`Invalid format: ${format}`);
    }
    if (!validAlgorithms.includes(algorithm)) {
      throw new Error(`Invalid algorithm: ${algorithm}`);
    }

    let cmdBits = [`genpkey -outform PEM -algorithm ${algorithm}`];
    let stdIn;

    if (paramFile) {
      cmdBits.push(`-paramfile ${paramFile}`);
    } else {
      Object.keys(pkeyOpts).forEach((key) => {
        cmdBits.push(`-pkeyopt ${key}:${pkeyOpts[key]}`);
      });
    }

    if (encrypted) {
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

    const { command, stdOut } = await this.runCommand({ cmd: cmdBits.join(' '), stdIn });

    return { key: stdOut, cmd: command };

    // TODO: convert to PKCS1

    // if(format=='PKCS8') {
    // 	this.runCommand({ cmd, stdin: options.encryption.password}, function(err, out) {
    // 		//console.log(err);
    // 		if(err) {
    // 			callback(err, false, false);
    // 		} else {
    // 			callback(false, out.stdout.toString(), [out.command + ' -out priv.key']);
    // 		}
    // 	});
    // } else if (format == 'PKCS1' ) {
    // 	this.runCommand({ cmd, stdin: options.encryption.password}, function(err, outkey) {
    // 		if(err) {
    // 			callback(err, false, false);
    // 		} else {
    // 			convertToPKCS1(outkey.stdout.toString(), options.encryption, function(err, out) {
    // 				if(err) {
    // 					callback(err, false, false);
    // 				} else {
    // 					callback(false, out.data, [ outkey.command + ' -out priv.key', out.command + ' -out priv.key' ]);
    // 				}
    // 			});
    // 		}
    // 	});
    // }
  }

  // TODO: generateCSR()
  // TODO: csr.selfSign()
  // TODO: ca.signCSR()
}
