function OTP(otp) {
    this._otp = otp;
}

OTP.prototype.get_otp = function() {
    return this._otp;
};

exports.OTP = OTP;
