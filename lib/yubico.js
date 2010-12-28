var http = require('http');
var querystring = require('querystring');
var crypto = require('crypto');

var base64 = require('./extern/base64');
var sprintf = require('./extern/sprintf').sprintf;

var OTP = require('./otp').OTP;
var constants = require('./constants');
var exceptions = require('./exceptions');
var utils = require('./utils');

function Yubico(client_id, key, use_https) {
    this._client_id = client_id;
    this._key = (key !== null) ? base64.decode(key) : null;
    this._use_https = use_https || true;
}

/**
 * Verify the OTP token.
 *
 * @param {Function} callback
 */
Yubico.prototype.verify = function(otp, timestamp, sl, timeout, callback) {
    var otp_, timestamp_, sl_, timeout_, nonce, query_string;
    otp_ = new OTP(otp);
    sl_ = sl || false;
    timeout_ = timeout || constants.TIMEOUT * 1000;

    if (typeof timestamp === 'function') {
        timestamp_ = false;
        callback_ = timestamp;
    }
    else {
        callback_ = callback;
    }

    nonce = base64.encode(utils.randstr(40));
    nonce = nonce.substr(0, 35);
    query_string = this._generate_query_string(otp_.get_otp(), nonce, timestamp_, sl_, (timeout_ / 1000));

    this._verify_token(otp, query_string, timeout_, function(err, success) {
        if (err) {
            callback_(err, false);
            return;
        }

        callback_(null, true);
    });
};

Yubico.prototype.verify_multi = function(otp_list, max_time_window, timeout) {
};

/**
 * Verify the provided token.
 *
 * @param {OTP} otp OTP instance.
 * @param {String} query_string Query string which is appended to all the URLs.
 * @param {Number} timeout Number of seconds to wait for sync responses; if
 *                         absent, let the server decides.
 * @param {Function} callback Callback which is called with a possible error
 *                            as the first argument and true as the second
 *                            one if the provided OTP is valid.
 */
Yubico.prototype._verify_token = function(otp, query_string, timeout, callback) {
    var i, client, request, host, port, path, error;
    var timeout_ids = [], client_objects = [], request_objects = [];
    var got_response = false, callback_called = false;

    var call_callback = function(err, success) {
        if (callback_called) {
            return;
        }

        callback_called = true;
        callback(err, success);
    };

    var handle_response = function(response, client) {
        var data_buffer = [];

        if (got_response || callback_called) {
            return;
        }

        if (!client.verifyPeer()) {
            // Invalid SSL certificate
            error = exceptions.InvalidSSLCertificateError(client.getPeerCertificate());
            call_callback(error, false);
            return;
        }

        response.on('data', function(chunk) {
            data_buffer.push(chunk);
        });

        response.on('end', function() {
            var response, split, parsed_response, signature, parameters;
            var status, generated_signature, error;
            response = data_buffer.join('');

            // Only wait for a single positive or negative response
            handle_got_response();

            status = response.match('status=([a-zA-Z0-9_]+)');
            if (!status) {
                call_callback(new Error('Missing status attribute'), false);
                return;
           }

            status = status[1].trim().toLowerCase();

            if (this._key) {
                // Verify the response signature
                parsed_response = this.parse_parameters_from_respone(response);
                signature = parsed_response[0];
                parameters = parsed_response[1];
                generated_signature = this.generate_message_signature(parameters, this._key);

                if (signature !== generated_signature) {
                    error = new exceptions.SignatureVerificationError(generated_signature, signature);
                    call_callback(error, false);
                    return;
                }
            }

            if (status.toLowerCase() === 'ok') {
                call_callback(null, true);
                return;
            }
            else if (status === 'no_such_client') {
                error = new exceptions.InvalidClientError(this._client_id);
                call_callback(error);
                return;
            }
            else if (status === 'replayed_otp') {
                error = new exceptions.StatusCodeError('REPLAYED_OTP');
                call_callback(error, false);
                return;
            }

            error = new exceptions.StatusCodeError(status);
            call_callback(error, false);
        });
    };

    var handle_error = function(err) {
        client.removeAllListeners('response');
        call_callback(err, false);
    };

    var handle_timeout = function(client) {
        if (got_response || callback_called) {
            return;
        }

        if (client.writable) {
            client.destroy();
        }

        client.removeAllListeners('response');
        call_callback(new exceptions.ConnectionTimeoutError(timeout), false);
    };

    var handle_got_response = function() {
        var i, client_object, request_object, timeout_id;
        got_response = true;

        for (i = 0; i < client_objects.length; i++) {
            client_object = client_objects[i];
            client_object.removeAllListeners('error');

            if (client_object.writable) {
                client_object.destroy();
            }
        }

        for (i = 0; i < request_objects.length; i++) {
            request_object = request_objects[i];
            request_object.removeAllListeners('response');
        }

        for (i = 0; i < timeout_ids.length; i++) {
            timeout_id = timeout_ids[i];
            clearTimeout(timeout_id);
        }
    };

    port = (this._use_https) ? 443 : 80;
    for (i = 0; i < constants.API_HOSTS.length ; i++) {
        host = constants.API_HOSTS[i];
        path = sprintf('%s?%s', constants.API_PATH, query_string);

        client = http.createClient(port, host, this._use_https);
        request = client.request('GET', path, {'host': host});
        request.end();

        client.on('error', handle_error);

        (function(client) {
            var timeout_id;

            request.on('response', function(response) {
                handle_response(response, client);
            });

            timeout_id = setTimeout(function() {
                handle_timeout(client);
            }, timeout);

            timeout_ids.push(timeout_id);
        })(client);

        client_objects.push(client);
        request_objects.push(request);

    }
};

/**
 * Generate a query string which is sent to the validation servers.
 *
 * @param {String} otp Yubikey token.
 * @param {String} nonce  16 to 40 characters long string with random data.
 * @param {String} sl A value 0 to 100 indicating percentage of syncing required
 *                    by client, or strings "fast" or "secure" to use
 *                    server-configured values; if
 *                    absent, let the server decides.
 * @param {Number} timeout Number of seconds to wait for sync responses; if
 *                         absent, let the server decide.
 * @return {String} Generated query string.
 */
Yubico.prototype._generate_query_string = function(otp, nonce, timestamp, sl, timeout) {
    var data;
    data = { 'id': this._client_id,
             'otp': otp,
             'nonce': nonce
    };

    if (timestamp) {
        data['timestamp'] = 1;
    }

    if (sl) {
        if (sl < 0 || sl > 100 && [ 'fast', 'secure' ].indexOf(sl) === -1) {
            throw new Error('sl parameter value must be between 0 and 100 or string "fast" or "secure"');
        }

        data['sl'] = sl;
    }

    if (timeout) {
        data['timeout'] = timeout;
    }

    query_string = querystring.encode(data);

    if (this._key) {
        hmac_signature = this.generate_message_signature(query_string, this._key);
        query_string = sprintf('%s&h=%s', query_string, hmac_signature);
    }

    return query_string;
};

/**
 * Parse parameters from response.
 *
 * @param {String} response Response string
 * @return {Array} Array where the first member is parsed signature and the
 *                second one if the rest of the parsed response returned as
 *                a query string.
 */
Yubico.prototype._parse_parameters_from_response = function(response) {
    var i, split, pairs, pair, signature, query_string;

    pairs = response.split('\n');
    for (i = 0; i < pairs.length; i++) {
        pair = pairs[i].trim();

        if (pair === '') {
            continue;
        }

        split.push(pair);
    }

    signature = split[0].replace('h=', '');
    query_string = split.slice(1).join('&');

    return [ signature, query_string ];
};


/**
 * Generate HMAC-SHA1 signature for the given query string using the
 * provided key.
 *
 * @param {String} query_string Query string
 * @param {String} key Cryptographic key.
 * @return {String} base64 encoded signature.
 */
Yubico.prototype.generate_message_signature = function(query_string, key) {
    var i, pairs, pair, pairs_sorted, pairs_string, hmac, signature;
    pairs = query_string.split('&');

    pairs_sorted = [];
    for (i = 0; i < pairs.length; i++) {
        pair = pairs[i];
        pairs_sorted.push(pair);
    }

    pairs_sorted.sort();

    for (i = 0; i < pairs_sorted.length; i++) {
        pair = pairs[i];
        pairs[i] = pair.join('&');
    }

    pairs_string = pairs.join('&');

    hmac = crypto.createHmac('sha1', key);
    hmac.update(pairs_string);
    signature = hmac.digest('base64');

    return signature;
};

exports.Yubico = Yubico;
