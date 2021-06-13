const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    account: { type: Schema.Types.ObjectId, ref: 'Account'},
    token: String,
    expires: Date,
    created: { type: Date, default: Date.now },
    createdByIp: String,
    revoked: Date,
    revokedByIp: String,
    replacedByToken: String
});

schema.virtual('isExpired').get(() => {
    return Date.now() >= this.expires;
});

schema.virtual('isActive').get(() => {
    return !this.revoked && !this.isExpired;
});

module.exports = mongoose.model('RefreshToken', schema);