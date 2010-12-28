var http = require('http');
var querystring = require('querystring');
var crypto = require('crypto');

var base64 = require('./extern/base64');
var sprintf = require('./extern/sprintf').sprintf;

var OTP = require('./otp').OTP;
var constants = require('./constants');
var exceptions = require('./exceptions');
var utils = require('./utils');

/**
 *
 * @constructor
 * @param {Number} client_id Client ID
 * @param {String} key API key
 * @param {Boolean} use_https True to use HTTPS (defaults to true)
 *
 * Note: You can get both client_id and API key at https://upgrade.yubico.com/getapikey/
 */
function Yubico(client_id, key, use_https) {
    this._client_id = client_id;
    this._key = (key !== null) ? base64.decode(key) : null;
    this._use_https = use_https || true;
}

/**
 * Verify the OTP token.
 *
 * @param {Number} timeout Connection timeout in seconds (defaults to 15
 *                         seconds)
 * @param {Function} callback Callback which is called with a possible error
 *                            as the first argument and true as the second
 *                            one if the provided OTP is valid.
 */
Yubico.prototype.verify = function(otp, timeout, callback) {
    var timeout_, callback_, nonce;

    if (typeof timeout === 'function') {
        timeout_ = constants.TIMEOUT * 1000;
        callback_ = timeout;
    }
    else {
        timeout_ = timeout * 1000;
        callback_ = callback;
    }

    this._verify_token(otp, timeout_, function(err, success) {
        if (err) {
            callback_(err, false);
            return;
        }

        callback_(null, true);
    });
};

/**
 * Verify multiple OTP tokens.
 *
 * @param {Array} otp_list Array of OTP tokens.
 * @param {Number} max_time_window How many seconds can pass between the first
 *                 and the last OTP generation.
 * @param {Number} timeout Connection timeout in seconds (defaults to 15
 *                         seconds)
 * @param {Function} callback Callback which is called with a possible error
 *                            as the first argument and true as the second
 *                            one if all the provided OTPs are valid.
 */
Yubico.prototype.verify_multi = function(otp_list, max_time_window, timeout, callback) {
    var self = this;
    var max_time_window_, timeout_, callback_;
    var i, otp_list_length, otp, otp_object, device_id, otps = [], device_ids = [];
    var callback_called = false, result_count = 0;

    if (typeof max_time_window === 'function') {
        max_time_window_ = constants.MAX_TIME_WINDOW;
        timeout_ = (constants.TIMEOUT * 1000);
        callback_ = max_time_window;
    }
    else {
        max_time_window_ = max_time_window || constants.MAX_TIME_WINDOW;
        timeout_ = (timeout * 1000) || (constants.TIMEOUT * 1000);
        callback_ = callback;
    }

    var call_callback = function(err, success) {
        if (callback_called) {
            return;
        }

        callback_called = true;
        callback_(err, success);
    };

    var handle_got_result = function(err, result) {
        if (err) {
            call_callback(err, false);
            return;
        }

        result_count++;
        if (result_count === otp_list_length) {
            call_callback(null, true);
        }
        else {
            self._verify_token(otps.shift(), timeout_, handle_got_result);
        }
    };

    otp_list_length = otp_list.length;
    for (i = 0; i < otp_list_length; i++) {
        otp = otp_list[i];
        otp_object = new OTP(otp);
        device_id = otp_object.get_device_id();

        if (i > 0 && device_ids.indexOf(device_id) === -1) {
            callback_(new Error('OTPs contain different device IDs'), false);
            return;
        }

        device_ids.push(device_id);
        otps.push(otp);
    }

    this._verify_token(otps.shift(), timeout_, handle_got_result);
};

/**
 * Verify the provided token.
 *
 * @param {String} otp OTP token.
 * @param {Number} timeout Number of seconds to wait for sync responses; if
 *                         absent, let the server decides.
 * @param {Function} callback Callback which is called with a possible error
 *                            as the first argument and true as the second
 *                            one if the provided OTP is valid.
 */
Yubico.prototype._verify_token = function(otp, timeout, callback) {
    var self = this;
    var otp_, nonce, query_string;

    var i, client, request, host, port, path, error;
    var timeout_ids = [], client_objects = [], request_objects = [];
    var got_response = false, callback_called = false;
    var client_timed_out_count = 0;

    otp_ = new OTP(otp).get_otp();
    nonce = base64.encode(utils.randstr(40));
    nonce = nonce.substr(0, 30);
    query_string = this._generate_query_string(otp_, nonce, true, 75, (timeout / 1000));

    var call_callback = function(err, success) {
        if (callback_called) {
            return;
        }

        callback_called = true;
        callback(err, success);
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

    var clear_connect_timeout = function(timeout_id) {
        clearTimeout(timeout_id);
    };

    var handle_response = function(response, client, timeout_id) {
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

        clear_connect_timeout(timeout_id);

        response.on('data', function(chunk) {
            data_buffer.push(chunk);
        });

        response.on('end', function() {
            var response, split, parsed_response, signature, parameters;
            var status, response_otp, generated_signature, error;
            response = data_buffer.join('');

            status = response.match('status=([a-zA-Z0-9_]+)');
            response_otp = response.match('otp=([a-zA-Z0-9]+)');

            if (!status) {
                handle_got_response();

                call_callback(new Error('Missing status attribute'), false);
                return;
            }

            status = status[1].trim().toLowerCase();
            response_otp = response_otp[1].trim();
            if (otp !== response_otp) {
                handle_got_response();

                call_callback(new Error('OTP in the response does not match the' +
                                        ' provided OTP'), false);
                return;
            }

            if (self._key) {
                // Verify the response signature
                parsed_response = self._parse_parameters_from_response(response);
                signature = parsed_response[0];
                parameters = parsed_response[1];
                generated_signature = self._generate_message_signature(parameters, self._key);

                if (signature !== generated_signature) {
                    handle_got_response();

                    error = new exceptions.SignatureVerificationError(generated_signature, signature);
                    call_callback(error, false);
                    return;
                }
            }

            if (status.toLowerCase() === 'ok') {
                handle_got_response();

                call_callback(null, true);
                return;
            }
            else if (status === 'no_such_client') {
                handle_got_response();

                error = new exceptions.InvaliClientError(self._client_id);
                call_callback(error);
                return;
            }
            else if (status === 'replayed_otp' || status === 'bad_otp' || 
                     status === 'bad_signature') {
                handle_got_response();

                error = new exceptions.StatusCodeError(status);
                call_callback(error);
                return;
            }
            else if (status === 'replayed_request') {
                return;
            }

            handle_got_response();
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

        client_timed_out_count++;
        client.removeAllListeners('response');

        if (client_timed_out_count === client_objects.length) {
            call_callback(new exceptions.ConnectionTimeoutError(timeout));
        }
    };

    port = (this._use_https) ? 443 : 80;
    for (i = 0; i < constants.API_HOSTS.length ; i++) {
        host = constants.API_HOSTS[i];
        path = sprintf('%s?%s', constants.API_PATH, query_string);

        client = http.createClient(port, host, this._use_https);
        request = client.request('GET', path, {
            'host': host,
            'User-Agent': sprintf('NodeJS Yubico library v%s.%s.%s',
                                  constants.VERSION[0], constants.VERSION[1],
                                  constants.VERSION[2])
        });

        request.end();
        client.on('error', handle_error);

        (function(client) {
            var timeout_id;

            timeout_id = setTimeout(function() {
                handle_timeout(client);
            }, timeout);

            request.on('response', function(response) {
                handle_response(response, client, timeout_id);
            });

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
    var data, query_string, hmac_signature;

    data = { 'id': this._client_id,
             'otp': otp,
             'nonce': nonce
    };

    if (timestamp) {
        data.timestamp = 1;
    }

    if (sl) {
        if (sl < 0 || sl > 100 && [ 'fast', 'secure' ].indexOf(sl) === -1) {
            throw new Error('sl parameter value must be between 0 and 100 or string "fast" or "secure"');
        }

        data.sl = sl;
    }

    if (timeout) {
        data.timeout = timeout;
    }

    query_string = querystring.encode(data);

    if (this._key) {
        hmac_signature = this._generate_message_signature(query_string, this._key);
        hmac_signature = hmac_signature.replace(/\+/g, '%2B');
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
    var i, split = [], pairs, pair, signature, query_string;

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
Yubico.prototype._generate_message_signature = function(query_string, key) {
    var i, pairs, pair, pairs_sorted, pairs_string, hmac, signature;
    pairs = query_string.split('&');

    pairs_sorted = [];
    for (i = 0; i < pairs.length; i++) {
        pair = pairs[i];
        pair = pair.split('=');
        pairs_sorted.push(pair);
    }

    pairs_sorted.sort();

    pairs = [];
    for (i = 0; i < pairs_sorted.length; i++) {
        pair = pairs_sorted[i];
        pairs[i] = pair.join('=');
    }

    pairs_string = pairs.join('&');

    hmac = crypto.createHmac('sha1', key);
    hmac.update(pairs_string);
    signature = hmac.digest('base64');

    return signature;
};

exports.Yubico = Yubico;
