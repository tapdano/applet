function ndefRecordHeader(MB, ME, CF, SR, IL, TNF) {
  let byte = (MB << 7) | (ME << 6) | (CF << 5) | (SR << 4) | (IL << 3) | TNF;
  let hexString = byte.toString(16).toUpperCase().padStart(2, '0');
  return hexString;
}

console.log(ndefRecordHeader(1, 0, 0, 1, 0, 0x01));

console.log(ndefRecordHeader(0, 1, 0, 1, 0, 0x05));

/*
00
ZZ - TOTAL LEN
91 - HEADER #1
01 - TYPE LEN
0C - PAYLOAD LEN (0C = 12 BYTES)
55 - TYPE ('U')
04 74 61 70 64 61 6E 6F 2E 63 6F 6D - PAYLOAD
55 - HEADER #2
00 - TYPE LEN
XX - PAYLOAD LEN
YY - PAYLOAD
*/