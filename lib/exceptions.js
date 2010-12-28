var sys = require('sys');

var sprintf = require('./extern/sprintf').sprintf;

function SignatureVerificationError(expected_signature, actual_signature) {
    this.name = 'SignatureVerificationError';
    this.message = sprintf('Signatured verification failed - ' +
                          'expected = %s, got = %s',
                           expected_signature, actual_signature);
    this.expected_signature = expected_signature;
    this.actual_signature = actual_signature;
}

sys.inherits(SignatureVerificationError, Error);

function InvalidClientError(client_id) {
    this.name = 'InvalidClientError';
    this.message = sprintf('Invalid client id: %s', client_id);
    this.client_id = client_id;
}

sys.inherits(InvalidClientError, Error);

function StatusCodeError(status_code) {
    this.name = 'StatusCodeError';
    this.message = sprintf('Error: %s', status_code);
    this.status_code = status_code;
}

sys.inherits(StatusCodeError, Error);

function InvalidSSLCertificateError(cert_info) {
    this.name = 'InvalidSSLCertificate';
    this.message = sprintf('Invalid SSL certificate: %s', JSON.stringify(cert_info));
    this.cert_info = cert_info;
}

function ConnectionTimeoutError(timeout_threshold) {
    this.name = 'ConnectionTimeout';
    this.message = sprintf('Connection timed out after %d seconds',
        (timeout_threshold / 1000));
    this.timeout_threshold = timeout_threshold;
}

sys.inherits(InvalidSSLCertificateError, Error);

exports.SignatureVerificationError = SignatureVerificationError;
exports.InvaliClientError = InvalidClientError;
exports.StatusCodeError = StatusCodeError;
exports.InvalidSSLCertificateError = InvalidSSLCertificateError;
exports.ConnectionTimeoutError = ConnectionTimeoutError;
