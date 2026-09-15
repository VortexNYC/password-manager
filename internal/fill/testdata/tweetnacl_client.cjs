// TweetNaCl client matching keepassxc-browser 1.10 (nacl.min.js + nacl-util.min.js).
// stdin: one JSON object. stdout: one JSON object.
const nacl = require(process.argv[2]);
nacl.util = require(process.argv[3]);

function incrementNonce(nonce) {
  const oldNonce = nacl.util.decodeBase64(nonce);
  const newNonce = oldNonce.slice(0);
  let c = 1;
  for (let i = 0; i < newNonce.length; ++i) {
    c += newNonce[i];
    newNonce[i] = c;
    c >>= 8;
  }
  return nacl.util.encodeBase64(newNonce);
}

const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const out = {};
switch (input.op) {
  case "keypair": {
    const kp = nacl.box.keyPair();
    out.publicKey = nacl.util.encodeBase64(kp.publicKey);
    out.secretKey = nacl.util.encodeBase64(kp.secretKey);
    break;
  }
  case "increment":
    out.nonce = incrementNonce(input.nonce);
    break;
  case "box": {
    const boxed = nacl.box(
      nacl.util.decodeUTF8(input.plain),
      nacl.util.decodeBase64(input.nonce),
      nacl.util.decodeBase64(input.theirPub),
      nacl.util.decodeBase64(input.secret),
    );
    if (!boxed) {
      out.error = "box failed";
      break;
    }
    out.message = nacl.util.encodeBase64(boxed);
    break;
  }
  case "open": {
    const plain = nacl.box.open(
      nacl.util.decodeBase64(input.message),
      nacl.util.decodeBase64(input.nonce),
      nacl.util.decodeBase64(input.theirPub),
      nacl.util.decodeBase64(input.secret),
    );
    if (!plain) {
      out.error = "open failed";
      break;
    }
    out.plain = nacl.util.encodeUTF8(plain);
    break;
  }
  default:
    out.error = "unknown op";
}
process.stdout.write(JSON.stringify(out));
