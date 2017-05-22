var util = require('util');
var http = require('http');
var https = require('https');
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
 * Note: You can get client_id and API key at https://upgrade.yubico.com/getapikey/
 */
function Yubico(client_id, key, use_https) {
    this._client_id = client_id;
    this._key = (key) ? base64.decode(key) : null;
    this._use_https = use_https !== false;

    if (this._use_https && process.version.indexOf('v0.3') !== -1) {
        util.error('https in node v0.3.x is currently broken, so you can\'t' +
                  ' use https when using node v0.3.x');
        this._use_https = false;
    }
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

    this._verify_token(otp, timeout_, false, function(err, success) {
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
    var time_first_otp, time_last_otp;
    var callback_called = false, result_count = 0;

    if (typeof max_time_window === 'function') {
        max_time_window_ = (constants.MAX_TIME_WINDOW / 0.125);
        timeout_ = (constants.TIMEOUT * 1000);
        callback_ = max_time_window;
    }
    else {
        max_time_window_ = (max_time_window / 0.125) || (constants.MAX_TIME_WINDOW / 0.125);
        timeout_ = (timeout * 1000) || (constants.TIMEOUT * 1000);
        callback_ = callback;
    }

    if (otp_list.length <= 1) {
        callback_(new Error('otp_list array must contain at least two tokens.'), false);
        return;
    }

    var call_callback = function(err, success) {
        if (callback_called) {
            return;
        }

        callback_called = true;
        callback_(err, success);
    };

    var parse_timestamp_from_response = function(response) {
        var parameters_array, parameters_object;
        parameters_array = self._parse_parameters_from_response(response);
        parameters_object = self._query_string_to_object(parameters_array[1]);

        return parameters_object.timestamp;
    };

    var check_time_window = function() {
        var delta;

        delta = (time_last_otp - time_first_otp);
        if (delta > max_time_window_) {
            return true;
        }

        return false;
    };

    var handle_got_result = function(err, result, response) {
        var time_window_reached, error;
        if (err) {
            call_callback(err, false);
            return;
        }

        if (result_count === 0) {
            time_first_otp = parse_timestamp_from_response(response);
        }

        if (result_count === otp_list_length - 1) {
            time_last_otp = parse_timestamp_from_response(response);
        }

        result_count++;
        if (result_count === otp_list_length) {
            time_window_reached = check_time_window();
            if (time_window_reached) {
                error = new exceptions.TimeWindowReachedError(max_time_window_);
                call_callback(error, false);
                return;
            }

            call_callback(null, true);
        }
        else {
            self._verify_token(otps.shift(), timeout_, true, handle_got_result);
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

    this._verify_token(otps.shift(), timeout_, true, handle_got_result);
};

/**
 * Verify the provided token.
 *
 * @param {String} otp OTP token.
 * @param {Number} timeout Number of seconds to wait for sync responses; if
 *                         absent, let the server decides.
 * @param {Boolean} return_response true to call callback with the response
 *                                  string as the last argument.
 * @param {Function} callback Callback which is called with a possible error
 *                            as the first argument, true as the second one
 *                            if the provided OTP is valid and the response
 *                            string as the third one if return_response equals
 *                            true.
 */
Yubico.prototype._verify_token = function(otp, timeout, return_response, callback) {
    var self = this;
    var otp_, nonce, query_string;

    var i, request, host, path, error;
    var timeout_ids = [], request_objects = [];
    var got_response = false, callback_called = false;
    var client_timed_out_count = 0;

    otp_ = new OTP(otp).get_otp();
    nonce = base64.encode(utils.randstr(40));
    nonce = nonce.substr(0, 30);
    query_string = this._generate_query_string(otp_, nonce, true, 75, (timeout / 1000));

    var call_callback = function(err, success, response) {
        if (callback_called) {
            return;
        }

        if (!return_response) {
            response = undefined;
        }

        callback_called = true;
        callback(err, success, response);
    };

    var handle_got_response = function() {
        var i, request_object, timeout_id;
        got_response = true;

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

    var handle_response = function(response, timeout_id) {
        var data_buffer = [];

        if (got_response || callback_called) {
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

                call_callback(new Error('Missing status attribute'), false, response);
                return;
            }

            status = status[1].trim().toLowerCase();
            response_otp = response_otp[1].trim();
            if (otp !== response_otp) {
                handle_got_response();

                call_callback(new Error('OTP in the response does not match the' +
                                        ' provided OTP'), false, response);
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
                    call_callback(error, false, response);
                    return;
                }
            }

            if (status.toLowerCase() === 'ok') {
                handle_got_response();

                call_callback(null, true, response);
                return;
            }
            else if (status === 'no_such_client' || status === 'bad_signature') {
                handle_got_response();

                error = new exceptions.InvaliClientError(self._client_id);
                call_callback(error, false, response);
                return;
            }
            else if (status === 'replayed_otp' || status === 'bad_otp') {
                handle_got_response();

                call_callback(null, false, response);
                return;
            }
            else if (status === 'replayed_request') {
                return;
            }

            handle_got_response();
            error = new exceptions.StatusCodeError(status);
            call_callback(error, false, response);
        });
    };

    var handle_error = function(err) {
        call_callback(err, false);
    };

    var handle_timeout = function(request) {
        if (got_response || callback_called) {
            return;
        }

        client_timed_out_count++;
        request.removeAllListeners('response');

        if (client_timed_out_count === request_objects.length) {
            call_callback(new exceptions.ConnectionTimeoutError(timeout));
        }
    };

    for (i = 0; i < constants.API_HOSTS.length ; i++) {
        host = constants.API_HOSTS[i];
        path = sprintf('%s?%s', constants.API_PATH, query_string);

        if (this._use_https) {
            request = https.request({hostname: host, path: path, rejectUnauthorized: true});
        }
        else {
            request = http.request({hostname: host, path: path});
        }

        (function(request) {
            var timeout_id;

            timeout_id = setTimeout(function() {
                handle_timeout(request);
            }, timeout);

            request.on('response', function(response) {
                handle_response(response, timeout_id);
            });

            timeout_ids.push(timeout_id);
        })(request);

        request.end();

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
 * Parse parameters from the response.
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
  * Convert a query string to an object.
 *
 * @param {String} query_string Query string (e.g. foo=bar&bar=baz)
 * @return {Object} Object where the key is a parameter name and the value is
 *                  is the parameter value.
 */
Yubico.prototype._query_string_to_object = function(query_string) {
    var i, pairs, pair, parameters = {};

    pairs = query_string.split('&');
    for (i = 0; i < pairs.length; i++) {
        pair = pairs[i].trim();

        if (pair === '') {
            continue;
        }

        pair = pair.split('=');
        parameters[pair[0]] = pair[1];
    }

    return parameters;
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
