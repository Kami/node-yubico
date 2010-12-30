var VERSION = [ 0, 1, 0 ];

var API_HOSTS = [ 'api.yubico.com',
                  'api2.yubico.com',
                  'api3.yubico.com',
                  'api4.yubico.com',
                  'api5.yubico.com',
];

var API_PATH = '/wsapi/2.0/verify';

var TIMEOUT = 15; // Default connection timeout (in seconds)
var MAX_TIME_WINDOW = 40; // How many seconds can pass between
                          // the first and the last OTP generation
                          // so that the OTP is still considered
                          // valid (only used in multi mode).
                          // default is 5 seconds (5 / 0.125)

exports.VERSION = VERSION;
exports.API_HOSTS = API_HOSTS;
exports.API_PATH = API_PATH;
exports.TIMEOUT = TIMEOUT;
exports.MAX_TIME_WINDOW = MAX_TIME_WINDOW;
