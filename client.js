const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
let registeredUsername = ""; 
const users = new Map();

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    socket.emit("registerPublicKey", {
      username,
      publicKey: publicKey,
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;
        if ((match = message.match(/^!secret (\w+)$/))) {
          targetUsername = match[1];
          console.log(`Now secretly chatting with ${targetUsername}`);
        } else if ((match = message.match(/^!impersonate (\w+)$/))) {
          
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          
          targetUsername = "";
          username = registeredUsername;
          console.log(`Chat reset. You are now broadcasting as ${username}`);
        } else {
          let textToSend = message;

          if (targetUsername) {
            const targetPubKey = users.get(targetUsername);
            if (targetPubKey) {
              textToSend = crypto.publicEncrypt(targetPubKey, Buffer.from(message)).toString("base64");
            } else {
              console.log(`[ERROR] Public key for ${targetUsername} not found.`);
              rl.prompt();
              return;
            }
          }

          const hash = crypto.createHash("sha256").update(textToSend).digest("hex");
          
          
          const signature = crypto.createSign("SHA256").update(textToSend).sign(privateKey, "hex");

          const meta = JSON.stringify({ targetUsername, signature });
          const payload = `${meta}|||${hash}|||${textToSend}`;

          socket.emit("message", { username, message: payload });
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
 
  const { username: senderUsername, message: senderMessage } = data;
  
  if (senderUsername !== registeredUsername) {
    const parts = senderMessage.split("|||");

    if (parts.length < 3) {
      console.log(`${senderUsername}: ${senderMessage}`);
      rl.prompt();
      return;
    }

    const metaStr = parts[0];
    const receivedHash = parts[1];
    const receivedText = parts.slice(2).join("|||");

    const computedHash = crypto.createHash("sha256").update(receivedText).digest("hex");
    if (computedHash !== receivedHash) {
      console.log(`\n[WARNING] The message from ${senderUsername} may have been changed during transmission!`);
    }

    let meta = {};
    try {
      meta = JSON.parse(metaStr);
    } catch (e) {
      console.log(`\n[WARNING] Message metadata corrupted.`);
    }

    const { targetUsername: msgTarget, signature } = meta;
    const senderPubKey = users.get(senderUsername);

    if (senderPubKey && signature) {
      const verify = crypto.createVerify("SHA256").update(receivedText);
      const isAuthentic = verify.verify(senderPubKey, signature, "hex");
      
      if (!isAuthentic) {
        console.log(`\n[WARNING] Impersonation attempt detected! This user (${senderUsername}) is fake.`);
      }
    } else if (!senderPubKey) {
      console.log(`\n[WARNING] Received message from unknown user: ${senderUsername}`);
    }

    let displayText = receivedText;

    if (msgTarget) {
      if (msgTarget === registeredUsername) {
        try {
          const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(receivedText, "base64")).toString("utf8");
          displayText = decrypted;
        } catch (e) {
          displayText = `[Decryption Failed - Message Tampered] Ciphertext: ${receivedText}`;
        }
      } else {
        displayText = `[Encrypted Secret to ${msgTarget}] ${receivedText}`;
      }
    }

    console.log(`${senderUsername}: ${displayText}`);
    rl.prompt();
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});