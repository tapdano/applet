const net = require('net');
const readline = require('readline');

const PROXY_PORT = 35964;
const SERVER_PROXY = 35963; //change on BixVReader.ini

let targetSocket = null;
let clientSocket = null;
const createTargetConnection = function () {
  targetSocket = net.createConnection({ port: SERVER_PROXY, host: '127.0.0.1' });

  targetSocket.on('data', async (data) => {
    const dataHex = data.toString('hex');
    writeClientConnection(data);
    if (dataHex == '00058012010000') {
      await restartTargetConnection();
    }
    if (dataHex == '000104') return;
    if (dataHex.startsWith('000f00a404')) return; // SELECT
    console.log('<< ', dataHex);
  });

  targetSocket.on('error', (err) => {
    //console.error('Target connection error:', err.message);
  });
}
const restartTargetConnection = async function (cs) {
  console.log('Restarting...');
  endTargetConnection();
  await sleep(1000);
  //console.log('Reconnecting targetSocket...');
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

const server = net.createServer((cs) => {
  clientSocket = cs;
  console.log('Client connected');

  createTargetConnection();

  clientSocket.on('data', (data) => {
    const dataHex = data.toString('hex');
    writeTargetConnection(data);
    if (dataHex == '00143bfa1800008131fe454a434f5033315632333298') return;
    if (dataHex == '00026999') return;
    console.log('>> ', dataHex + '\n');
  });

  clientSocket.on('end', () => {
    console.log('Client connection end');
    endTargetConnection();
  });

  clientSocket.on('error', (err) => {
    console.error('Client connection error:', err.message);
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