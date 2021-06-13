const config = require('../config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../_helpers/db');
const Role = require('../_helpers/role');

module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    validateResetToken,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({ email, password, ipAddress }) {
    const account = await db.Account.findOne({ email });

    if (!account || !bcrypt.compareSync(password, account.passwordHash))
        throw 'Email or password is incorrect';

    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    await refreshToken.save();

    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    const { account } = refreshToken;

    const newRefreshToken = generateRefreshToken(account, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;

    await refreshToken.save();
    await newRefreshToken.save();

    const jwtToken = generateJwtToken(account);

    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

async function revokeToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);

    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;

    await refreshToken.save();
}

async function register(params, origin) {
    if (await db.Account.findOne({ email: params.email })) 
        return await sendAlreadyRegisteredEmail(params.email, origin);

    const account = new db.Account(params);

    const isFirstAccount = (await db.Account.countDocuments({})) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    account.verificationToken = randomTokenString();

    account.passwordHash = hash(params.password);

    await account.save();
}

async function validateResetToken({ token }) {
    const account = await db.Account.findOne({ 
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!account)
        throw 'Invalid token';
}

async function getAll() {
    const accounts = await db.Account.find();
    return accounts.map(x => basicDetails(x));
}

async function getById(id) {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function create(params) {
    if (await db.Account.findOne({ email: params.email }))
        throw `Email ${params.email} is already registered`;

    const account = new db.Account(params);
    account.verfied = Date.now();

    account.passwordHash = hash(params.password);

    await account.save();

    return basicDetails(account);
}

async function update(id, params) {
    const account = await getAccount(id);

    if (params.email && account.email !== params.email && await db.Account.findOne({ email: params.email }))
        throw `Email ${params.email} is already taken`;

    if (params.password)
        params.passwordHash = hash(params.password);

    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();

    return basicDetails(account);
}

async function _delete(id) {
    const account = await getAccount(id);
    await account.remove();
}

async function getAccount(id) {
    if (!db.isValidId(id))
        throw 'Account not found';
    
    const account = await db.Account.findById(id);
    if (!account)
        throw 'Account not found';

    return account;
}

async function getRefreshToken(token) {
    const refreshToken = await db.RefreshToken.findOne({ token }).populate('account');
    if (!refreshToken || !refreshToken.isActive)
        throw 'Invalid token';

    return refreshToken;
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

function generateJwtToken(account) {
    return jwt.sign({
        sub: account.id,
        id: account.id
    },
    config.secret, 
    {
        expiresIn: '15m'
    });
}

function generateRefreshToken(account, ipAddress) {
    return new db.RefreshToken({
        account: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60  * 1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account) {
    const { id, fistName, lastName, email, role, created, updated } = account;
    return { id, fistName, lastName, email, role, created, updated };
}