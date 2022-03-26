import { NodeOpenSSL } from '../src/index';

let nodeOpenSSL: NodeOpenSSL;

beforeEach(() => {
  nodeOpenSSL = new NodeOpenSSL();
});

describe('getSupportedCiphers', () => {
  it('should return the expected cipher list', async () => {
    await nodeOpenSSL.getSupportedCiphers();
    // spawn spy to generate mock cipher list
    // expect getSupportedCiphers to return formatted mock cipher list
  });
});

describe('generatePrivateKey', () => {
  it('should do something', async () => {
    const result = await nodeOpenSSL.generatePrivateKey();
    console.log(result);
    // spawn spy to generate mock cipher list
    // expect getSupportedCiphers to return formatted mock cipher list
  });
});
// describe('init', () => {

//     it('should run openSSL with the expected command to acquire a cipher list', async () => {
//         await nodeOpenSSL.init();
//         // mock child_process
//         // expect spawn spy to be called with params
//     });

//     it('should throw an error when openSSL is not available', () => {

//     });
// });
