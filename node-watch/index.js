const { spawn, exec } = require('child_process');
const chokidar = require('chokidar');

let gradleProcess = null;

function killGradleProcess() {
  if (gradleProcess) {
    const pid = gradleProcess.pid;
    if (process.platform === "win32") {
      exec(`taskkill /PID ${pid} /F /T`, (error, stdout, stderr) => {
        if (error) {
          console.error(`Erro ao encerrar o processo: ${error}`);
        }
        console.log('Processo do Gradle encerrado.');
      });
    }
  }
}

// Função para iniciar ou reiniciar o gradlew runVSim
async function startGradleProcess() {
  if (gradleProcess) {
    console.log('Arquivo alterado. Reiniciando a tarefa...');
    killGradleProcess();
    await sleep(3000);
  }

  // Inicia um novo processo do Gradle
  gradleProcess = spawn('gradlew.bat', ['runVSim'], { 
    stdio: 'inherit', 
    shell: true
  });

  gradleProcess.on('close', (code) => {
    console.log(`Processo do Gradle encerrado com código ${code}`);
  });
}

// Inicializa o monitoramento do arquivo específico
const watcher = chokidar.watch([
  'src/main/java/tapdano/FIDO2Applet.java',
  'src/main/java/tapdano/Constants.java',
  'src/main/java/tapdano/TapDanoApplet.java'
], {
  ignored: /(^|[\/\\])\../, // ignora arquivos ponto
  persistent: true
});

// Evento disparado quando o arquivo é alterado
watcher.on('change', async (path) => {
  console.log(`Arquivo ${path} foi alterado.`);
  await startGradleProcess();
});

const sleep = function (ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
};

// Inicia o processo pela primeira vez
startGradleProcess();