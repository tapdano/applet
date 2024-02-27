function hexStringToArray(hexString) {
  const bytesArray = hexString.match(/.{1,2}/g).map(byte => `(byte)0x${byte}`);
  return bytesArray;
}

const hexString = "01000000014104AFD8EB506FC08E7DFBC59090DB3410EAFA6C29957E77AF0F348B4528999413DE87A241B5C253E0889CF4F061177D2631B6D4516708FD6711B931A2C6B10B82B14104439DCA134B613BA3510ED0769E8329AC71F996EBBBF1E1B654E0C197F418B8CBFF52F72E2B08B9360FA823771B39B6228CDB37CB729CCDE47F8D5FDE15CD9F319000";
const byteArray = hexStringToArray(hexString);
const strRet = JSON.stringify(byteArray).replaceAll('","', ', ').replace('["', '').replace('"]', '');

console.log(JSON.stringify(strRet));