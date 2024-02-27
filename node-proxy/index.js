const net = require('net');
const readline = require('readline');

const PROXY_PORT = 35964;
const SERVER_PROXY = 35963; //change on BixVReader.ini
const HIDE_COMMON = true;

let lastRecvAPDU = '';

let targetSocket = null;
let clientSocket = null;
const createTargetConnection = function () {
  targetSocket = net.createConnection({ port: SERVER_PROXY, host: '127.0.0.1' });

  targetSocket.on('data', async (data) => {
    const dataHex = data.toString('hex').toUpperCase();
    const dataLen = dataHex.slice(0, 4);
    let dataAPDU = dataHex.slice(4);
    lastRecvAPDU = dataAPDU;

    writeClientConnection(data);
    
    if (HIDE_COMMON) {
      if (dataAPDU == '02') return; // ?
      if (dataAPDU == '04') return; // RESET ?
      if (dataAPDU.startsWith('00A4')) { // SELECT
        if (dataAPDU == '00A404000BA0000003974349445F0100') return; // "Microsoft PNP AID"
        if (dataAPDU == '00A4040009A00000039742544659')     return; // "Microsoft IDMP AID"
        if (dataAPDU == '00A4040009A0000003974254465900')   return; // "Microsoft IDMP AID"
        if (dataAPDU == '00A4040409A0000003974254465900')   return; // "Microsoft IDMP AID" (FILE)
        if (dataAPDU == '00A4040009A00000030800001000')     return; // "Personal Identity Verification (PIV) / ID-ONE PIV BIO"
        if (dataAPDU == '00A4000C023FFF')                   return; // SELECT FILE
      }
      if (dataAPDU == '00CA7F6800') return; // GET DATA
    }
    if (dataAPDU == '00A4040008A0000006472F000100') dataAPDU += ' (SELECT FIDO2)';
    if (dataAPDU.startsWith('8010')) { //FIDO2 - CTAP
      const cmdByte = dataAPDU.slice(10, 12);
      if (cmdByte == '04') dataAPDU += ' (FIDO2 - GET_INFO)';
      if (cmdByte == '01') dataAPDU += ' (FIDO2 - CMD_MAKE_CREDENTIAL)';
      if (cmdByte == '02') dataAPDU += ' (FIDO2 - GET_ASSERTION)';
    }
    console.log('[PC]:', dataAPDU);
    if (dataAPDU == '8012010000') {
      await restartTargetConnection();
    }
  });

  targetSocket.on('connect', (err) => {
    console.log('[PC]: Connected\n');
  });

  targetSocket.on('end', () => {
    console.log('[PC]: End\n');
    endTargetConnection();
  });

  targetSocket.on('error', (err) => {
    //console.log('[PC]: Error: ', err.message + '\n');
  });
}
const restartTargetConnection = async function (cs) {
  console.log('[Restarting]...');
  endTargetConnection();
  await sleep(1000);
  createTargetConnection();
};
const endTargetConnection = function() {
  try {
    targetSocket.end();
  } catch (error) {
  }
};
const writeTargetConnection = function(data) {
  try {
    targetSocket.write(data);
  } catch (error) {
  }
};
const endClientConnection = function() {
  try {
    clientSocket.end();
  } catch (error) {
  }
};
const writeClientConnection = function(data) {
  try {
    clientSocket.write(data);
  } catch (error) {
  }
};

const server = net.createServer(async (cs) => {
  clientSocket = cs;
  console.log('[SC]: Connected\n');

  endTargetConnection();
  await sleep(1000);  
  createTargetConnection();

  clientSocket.on('data', (data) => {
    const dataHex = data.toString('hex').toUpperCase();
    const dataLen = dataHex.slice(0, 4);
    const dataAPDU = dataHex.slice(4);
    writeTargetConnection(data);
    if (HIDE_COMMON) {
      if (dataAPDU == '3BFA1800008131FE454A434F5033315632333298') return; // ATR (Answer To Reset)
      if (dataAPDU == '6999') { // Apple selection failed
        if (lastRecvAPDU == '00A404000BA0000003974349445F0100')   return; // "Microsoft PNP AID"
        if (lastRecvAPDU == '00A4040009A00000039742544659')       return; // "Microsoft IDMP AID"
        if (lastRecvAPDU == '00A4040009A0000003974254465900')     return; // "Microsoft IDMP AID"
        if (lastRecvAPDU == '00A4040409A0000003974254465900')     return; // "Microsoft IDMP AID" (FILE)
        if (lastRecvAPDU == '00A4040009A00000030800001000')       return; // "Personal Identity Verification (PIV) / ID-ONE PIV BIO"
      }
      if (dataAPDU == '6986') { // Command not allowed
        if (lastRecvAPDU == '00CA7F6800')     return; // GET DATA
        if (lastRecvAPDU == '00A4000C023FFF') return; // SELECT FILE
      }
    }
    console.log('[SC]:', dataAPDU + '\n');
  });

  clientSocket.on('end', () => {
    console.log('[SC]: End\n');
    endTargetConnection();
  });

  clientSocket.on('error', (err) => {
    console.log('[SC]: Error: ', err.message + '\n');
    endTargetConnection();
    endClientConnection();
  });
});

server.listen(PROXY_PORT, '127.0.0.1', () => {
  console.log('Proxy server listening on port ' + PROXY_PORT);
});

server.on('error', (err) => {
  console.error('Proxy server error:', err);
});

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
rl.on('line', async (input) => {
  if ((input === 'r') || (input === 'R')) {
    await restartTargetConnection();
  }
});

const sleep = function (ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
};