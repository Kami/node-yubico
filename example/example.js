var sys = require('sys');

var sprintf = require('../lib/extern/sprintf').sprintf;

var Yubico = require('../index').Yubico;

var argv = process.argv;

if (argv[0].lastIndexOf('node') === argv[0].length - 4) {
    argv = argv.slice(2);
}
else {
    argv = argv.slice(1);
}

var mode = argv[0];

if ([ 'single', 'multi' ].indexOf(mode) === -1) {
    sys.puts('Usage: node example.js single|multi client_id [secret_key|null] otp [otp 2]');
    process.exit(1);
}

var expected_args = (mode === 'single') ? 3 : 4;

var func, args;
argv = argv.slice(1);

if (argv.length !== expected_args) {
    args = (mode === 'single') ? 'single client_id [secret_key] otp' :
                                  'multi client_id [secret_key] otp_1 otp_2';
    sys.puts(sprintf('Usage: node example.js %s', args));
    process.exit(1);
}

var client_id = argv[0];
var secret_key = (argv[1] === 'null' || argv[1] === 'none') ? null : argv[1];

var yubico = new Yubico(client_id, secret_key);

if (mode === 'single') {
    func = yubico.verify;
    args = argv[2];
}
else if (mode === 'multi') {
    func = yubico.verify_multi;
    args = argv.slice(2);
}

func.call(yubico, args, function(err, success) {
    if (err) {
        sys.print('Token validation failed: ' + err.message);
        return;
    }

    sys.print('Success, the provided token is valid!');
});
