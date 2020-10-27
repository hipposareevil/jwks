const fs = require('fs');
const jose = require('node-jose');

const args = process.argv.slice(2);

const jwt = fs.readFileSync(args[0]).toString();
const publicKey = fs.readFileSync(args[1]);

(async () => {
	const key = await jose.JWK.asKey(publicKey, 'pem');
	const verifier = jose.JWS.createVerify(key);
	const verified = await verifier
		.verify(jwt)
		.catch(()=>{});
	// coerce to a truthy value
    const isVerified = !!verified;
    process.stdout.write("verified? " + isVerified + "\n");
	process.exit(false == isVerified);
})();
