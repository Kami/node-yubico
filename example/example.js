var sys = require('sys');

var Yubico = require('../index').Yubico;

var argv = process.argv;

if (argv[0].lastIndexOf('node') === argv[0].length - 4) {
    argv = argv.slice(2);
}
else {
    argv = argv.slice(2);
}

if (argv.length !== 3) {
    sys.puts('Usage: node example.js client_id [secret_key] otp');
    process.exit(1);
}

var client_id = argv[0];
var secret_key = (argv[1] === 'null' || argv[1] === 'none') ? null : argv[1];
var otp = argv[2];

var yubico = new Yubico(client_id, secret_key);
yubico.verify(otp, function(err, success) {
    if (err) {
        sys.print('Token validation failed: ' + err.message);
        return;
    }

    sys.print('Success, the provided token is valid!');
});
