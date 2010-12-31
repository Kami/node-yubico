var Yubico = require('../lib/yubico').Yubico;
var OTP = require('../lib/otp').OTP;

exports['test otp class'] = function(assert, beforeExit) {
    var otp = new OTP('vvegvftndfilcrfhrbggkfrbbijegfbgfgttjbtdtcnt');

    assert.equal(otp.get_otp(), 'vvegvftndfilcrfhrbggkfrbbijegfbgfgttjbtdtcnt');
    assert.equal(otp.get_device_id(), 'vvegvftndfil');
};

exports['test _parse_parameters_from_response'] = function(assert, beforeExit) {
    var response = 'h=ckbn7gh0C/qsTciVqcxpQ8yOqWY=\n' +
                   't=2010-12-30T14:30:12Z0264\n' +
                   'otp=vvegefendfulhrrihgvibljnnnbikjhnbrtfjlkltvvg\n' +
                   'nonce=UlVyeUFvU1lVM3FLT0tIeHczWUJpN0\n' +
                   'sl=75\n' +
                   'timestamp=10222212\n' +
                   'sessioncounter=1563\n' +
                   'sessionuse=3\n' +
                   'status=OK\n';

    var signature = 'ckbn7gh0C/qsTciVqcxpQ8yOqWY=';
    var query_string = 't=2010-12-30T14:30:12Z0264&otp=vvegefendfulhrrihgvibljnnnbikjhnbrtfjlkltvvg&nonce=UlVyeUFvU1lVM3FLT0tIeHczWUJpN0&sl=75&timestamp=10222212&sessioncounter=1563&sessionuse=3&status=OK';
    var yubico = new Yubico('1234');
    var result = yubico._parse_parameters_from_response(response);

    assert.equal(signature, result[0]);
    assert.equal(query_string, result[1]);
};

exports['test _query_string_to_object'] = function(assert, beforeExit) {
    var query_string = 't=2010-12-30T14:30:12Z0264&otp=vvegefendfulhrrihgvibljnnnbikjhnbrtfjlkltvvg&nonce=UlVyeUFvU1lVM3FLT0tIeHczWUJpN0&sl=75&timestamp=10222212&sessioncounter=1563&sessionuse=3&status=OK';
    var obj = {
        't': '2010-12-30T14:30:12Z0264',
        'otp': 'vvegefendfulhrrihgvibljnnnbikjhnbrtfjlkltvvg',
        'nonce': 'UlVyeUFvU1lVM3FLT0tIeHczWUJpN0',
        'sl': '75',
        'timestamp': '10222212',
        'sessioncounter': '1563',
        'sessionuse': '3',
        'status': 'OK'
    };

    var yubico = new Yubico('1234');
    var result = yubico._query_string_to_object(query_string);

    assert.deepEqual(obj, result);
};

exports['test _generate_message_signature'] = function(assert, beforeExit) {
    var query_string = 'foo=bar&bar=baz';
    var key = 'key1234';
    var signature = 'NDzpNpiUsBXWYtLS+F+BmATz+w4=';

    var yubico = new Yubico('1234');
    var result = yubico._generate_message_signature(query_string, key);

    assert.equal(signature, result);
};

exports['test _generate_query_string'] = function(assert, beforeExit) {
    var otp = 'vvegefendfulhrrihgvibljnnnbikjhnbrtfjlkltvvg';
    var nonce = 'UlVyeUFvU1lVM3FLT0tIeHczWUJpN0';
    var timestamp = true;
    var sl = 50;
    var timeout = 15;
    var query_string = 'id=1234&otp=vvegefendfulhrrihgvibljnnnbikjhnbrtfjlkltvvg&nonce=UlVyeUFvU1lVM3FLT0tIeHczWUJpN0&timestamp=1&sl=50&timeout=15';

    var yubico1 = new Yubico('1234');
    var yubico2 = new Yubico('1234', 'key1234');

    var signature = yubico2._generate_message_signature(query_string, yubico2._key);

    var result1 = yubico1._generate_query_string(otp, nonce, timestamp, sl, timeout);
    var result2 = yubico2._generate_query_string(otp, nonce, timestamp, sl, timeout);

    assert.equal(query_string, result1);
    assert.equal(query_string + '&h=' + signature, result2);
};
