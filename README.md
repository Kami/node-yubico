# Yubico
Node library for validating Yubico One Time Passwords (OTPs) based on the [validation protocol version 2.0](http://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20).

# Installation

    npm install yubico

# Usage

Create a new instance of the Yubico object and call `verify()` or `verify_multi()` method.

    var yubico = new Yubico(client_id, api_key, use_https)

Parameters:

* `client_id` - client id
* `key` - API key (optional)
* `use_https` true to use https (defaults to `true`)

Response message HMAC signature is only verified if an API key is provided so you are encouraged to provide it.

You can get both client_id and the api key at [https://upgrade.yubico.com/getapikey/](https://upgrade.yubico.com/getapikey/).

## Validating a single token

    yubico.verify(otp_token, timeout, callback)

Parameters:

* `otp` - token generated by the Yubikey
* `timeout` - connection timeout in seconds (defaults to 15 seconds)
* `callback` - a callback which is called with an error as the first argument if the Yubikey validation fails and `true` as the second one if the provided token is valid.

## Validating multiple tokens

    yubico.verify_multi(otp_list, max_time_window, timeout, callback)

* `otp_list` - an array of Yubikey tokens. Tokens are validated in the provided order so the order matters (tokens must be provided in the same order as they were generated)
* `max_time_window` - how many seconds can pass between the first token and the last token generation so that the result is still considered valid (defaults to 5 seconds)
* `timeout` - connection timeout in seconds (defaults to 15 seconds)
* `callback` - a callback which is called with an error as the first argument if the Yubikey validation fails and `true` as the second one if the provided token is valid.

# Example

Example is located in `example/example.js`.

## Validating a single token (example)

    node example/example.js single client_id [secret_key|null] otp

## Validating multiple tokens (example)

    node example/example.js multi client_id [secret_key|null] otp_1 otp_2

# History

02.02.2010 - v0.1.2:

* Allow package to be used with node >= 0.3.0
* Don't use https if node version >= 0.3.0 or use_https equals False
* Update tests so it works with a new version of expresso

31.12.2010 - v0.1.1:

* Verify time window in the multi mode
* Throw exception if none or only a single token is provided in the multi mode
* Always take "max_time_window" argument in seconds and convert it internally
* Add tests

28.12.2010 - v0.1.0:

* Initial release
