function OTP(otp) {
    this._otp = otp;
    this._device_id = this.get_otp().substr(0, 12);
}

OTP.prototype.get_otp = function() {
    return this._otp;
};

OTP.prototype.get_device_id = function() {
    return this._device_id;
};

exports.OTP = OTP;
