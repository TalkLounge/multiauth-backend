require("dotenv").config();
const defaults = require("defaults");
const fs = require("fs");
const { createAvatar } = require("@dicebear/avatars");
const style = require("@dicebear/avatars-identicon-sprites");
const queries = require("./queries.js");
const { Pool } = require("pg");
const { createHash } = require("crypto");
const bcrypt = require("bcrypt");
const cors = require("cors");
const bearerToken = require("express-bearer-token");
const bodyParser = require("body-parser");
const parser = require("ua-parser-js");
const cookieParser = require("cookie-parser");
const express = require("express");
const https = require("https");
const { spawn } = require("child_process");
const { createClient } = require("redis");
const addrs = require("email-addresses");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const app = express();

/*
TODO

trim post values
db function
clear _expire keys
body.password to (body.password || "") to fix crash
Email can be blocked by someone who knows the other person's email
wrap db init in async function
*/

const OPTIONS = defaults(process.env, {
    NODE_ENV: "production",
    POSTGRES_HOSTNAME: "localhost",
    POSTGRES_PORT: 5432,
    POSTGRES_USER: "postgres",
    POSTGRES_PASSWORD: "postgres",
    POSTGRES_DATABASE: "multiauth",
    POSTGRES_MAX_CONNECTIONS: 20,
    REDIS_HOSTNAME: "localhost",
    REDIS_PORT: 6379,
    PORT: 80,
    HOSTNAME: "0.0.0.0",
    HTTPS: false,
    CERT_PRIV: undefined,
    CERT_PUB: undefined,
    CERT_CA: undefined,
    URL: "http://0.0.0.0:80",
    FRONTEND_URL: "http://0.0.0.0:80",
    REDIRECT_URLS: undefined,
    ROLES: undefined,
    BEARERS: undefined,
    EMAIL_SENDER: "example@example.org",
    RATELIMIT_GLOBAL_LIMIT: 1000,
    RATELIMIT_GLOBAL_WINDOW: 3600,
    RATELIMIT_WRONG_BEARER_CLIENT_LIMIT: 5,
    RATELIMIT_WRONG_BEARER_CLIENT_WINDOW: 3600,
    RATELIMIT_NEW_ACCOUNT_LIMIT: 50,
    RATELIMIT_NEW_ACCOUNT_WINDOW: 3600,
    RATELIMIT_WRONG_BEARER_SERVER_LIMIT: 1,
    RATELIMIT_WRONG_BEARER_SERVER_WINDOW: 3600,
    RATELIMIT_CHANGE_NAME_LIMIT: 10,
    RATELIMIT_CHANGE_NAME_WINDOW: 86400,
    RATELIMIT_WRONG_PASSWORD_LIMIT: 5,
    RATELIMIT_WRONG_PASSWORD_WINDOW: 3600,
    RATELIMIT_CHANGE_EMAIL_LIMIT: 10,
    RATELIMIT_CHANGE_EMAIL_WINDOW: 86400,
    RATELIMIT_WRONG_EMAIL_CONFIRM_LIMIT: 5,
    RATELIMIT_WRONG_EMAIL_CONFIRM_WINDOW: 3600,
    RATELIMIT_WRONG_TOTP_LIMIT: 5,
    RATELIMIT_WRONG_TOTP_WINDOW: 3600,
    RATELIMIT_WRONG_NAME_LIMIT: 5,
    RATELIMIT_WRONG_NAME_WINDOW: 3600
});

const OPTIONSARRAY = {
    REDIRECT_URLS: OPTIONS.REDIRECT_URLS.replace(" ", "").split(","),
    ROLES: OPTIONS.ROLES.replace(" ", "").split(","),
    BEARERS: OPTIONS.BEARERS.replace(" ", "").split(",")
}

const pool = new Pool({
    host: OPTIONS.POSTGRES_HOSTNAME,
    port: OPTIONS.POSTGRES_PORT,
    user: OPTIONS.POSTGRES_USER,
    password: OPTIONS.POSTGRES_PASSWORD,
    database: OPTIONS.POSTGRES_DATABASE,
    max: OPTIONS.POSTGRES_MAX_CONNECTIONS,
});

const client = createClient({
    socket: {
        host: OPTIONS.REDIS_HOSTNAME,
        port: OPTIONS.REDIS_PORT
    }
});
client.connect();

for (const _ in queries.init) {
    pool.query(queries.init[_]);
}

for (const _ in OPTIONSARRAY.ROLES) {
    pool.query(queries.insertRole, [OPTIONSARRAY.ROLES[_]]);
}

pool.query(queries.insertUserRole, [1, 1]);
pool.query(queries.insertUserRole, [1, 2]);

async function rateLimitCheck(req, res, name, limit) {
    limit = parseInt(limit);
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const key = `multiauth:${name}-${ip}`;
    const value = parseInt(await client.get(key));
    if (value && value >= limit) {
        res.header("X-RateLimit-Limit", limit);
        res.header("X-RateLimit-Remaining", Math.max(limit - value, 0));
        res.header("X-RateLimit-Reset", parseInt(await client.PTTL(key) / 1000));
        res.status(429);
        res.end("Too Many Requests");
        return true;
    }
}

async function rateLimitIncrease(req, res, name, limit, window) {
    limit = parseInt(limit);
    window = parseInt(window);
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const key = `multiauth:${name}-${ip}`;
    let value = parseInt(await client.get(key));

    await client.incr(key);
    if (!value) {
        value = 0;
        await client.PEXPIRE(key, 1000 * window);
    }
    value++;

    res.header("X-RateLimit-Limit", limit);
    res.header("X-RateLimit-Remaining", Math.max(limit - value, 0));
    res.header("X-RateLimit-Reset", parseInt(await client.PTTL(key) / 1000));
}

async function rateLimit(req, res, name, limit, window, next) {
    if (await rateLimitCheck(req, res, name, limit)) {
        return true;
    }

    await rateLimitIncrease(req, res, name, limit, window);

    if (next) {
        next();
    }
}

async function authorizeClient(req, res, next) {
    if (await rateLimitCheck(req, res, "wrongBearerClient", OPTIONS.RATELIMIT_WRONG_BEARER_CLIENT_LIMIT)) {
        return;
    }

    if (!req.token) {
        sendUnauthorized(res, "Authorization Bearer not provided");
        return;
    }

    const data = (await pool.query(queries.selectUserLogin, [hash(req.token)])).rows[0];
    if (!data) {
        await rateLimitIncrease(req, res, "wrongBearerClient", OPTIONS.RATELIMIT_WRONG_BEARER_CLIENT_LIMIT, OPTIONS.RATELIMIT_WRONG_BEARER_CLIENT_WINDOW);
        sendUnauthorized(res, "Unauthorized");
        return;
    }

    req.user = (await pool.query(queries.selectUser, [data.users_id])).rows[0];
    next();
}

async function authorizeServer(req, res, next) {
    if (await rateLimitCheck(req, res, "authorizationServer", OPTIONS.RATELIMIT_WRONG_BEARER_SERVER_LIMIT)) {
        return;
    }

    if (!req.token) {
        sendUnauthorized(res, "Authorization Bearer not provided");
        return;
    }

    if (!OPTIONSARRAY.BEARERS.includes(req.token)) {
        await rateLimitIncrease(req, res, "authorizationServer", OPTIONS.RATELIMIT_WRONG_BEARER_SERVER_LIMIT, OPTIONS.RATELIMIT_WRONG_BEARER_SERVER_WINDOW);
        sendUnauthorized(res, "Unauthorized");
        return;
    }

    next();
}

app.use(cors());
app.use(bearerToken());
app.use(bodyParser.json());
app.set("json spaces", 40);
app.use(cookieParser());

function send(res, data) {
    if (data) {
        return res.json(data);
    }
    res.end();
}

function sendUnauthorized(res, error) {
    res.status(401);
    res.end(error);
}

function sendBadRequest(res, error) {
    res.status(400);
    res.end(error);
}

function isSet(variable) {
    return typeof (variable) != "undefined" && variable.length != 0;
}

function inputCheck(res, inputChecks) {
    for (let i = 0; i < inputChecks.length; i = i + 2) {
        if (inputChecks[i]) {
            sendBadRequest(res, inputChecks[i + 1]);
            return true;
        }
    }
}

function generateToken(len) {
    let token = "";
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (var i = 0; i < len; i++) {
        token += chars.charAt(Math.floor(Math.random() * 64));
    }
    return token;
}

function isAllowedRedirectURL(url) {
    for (let i = 0; i < OPTIONSARRAY.REDIRECT_URLS.length; i++) {
        if (url.startsWith(OPTIONSARRAY.REDIRECT_URLS[i])) {
            return true;
        }
    }
}

function hash(input) {
    for (let i = 0; i < 5000; i++) { // Hash 5000 times because sponsorblock does it too https://wiki.sponsor.ajay.app/w/API_Docs#Local_userID_vs_Public_userID
        input = createHash("sha256").update(input).digest("hex");
    }
    return input;
}

async function insertDevice(device) {
    if (!device) {
        return;
    }
    const data = (await pool.query(queries.selectDevice, [device])).rows[0];
    if (!data) {
        return (await pool.query(queries.insertDevice, [device])).rows[0].id;
    }
    return data.id;
}

async function mail(to, subject, html) {
    return new Promise(resolve => {
        const echo = spawn("echo", [html]);
        const mail = spawn("mail", ["-s", subject, `-aFrom:${OPTIONS.EMAIL_SENDER}`, to], { stdio: [echo.stdout, "pipe"] });

        mail.on("close", () => {
            resolve();
        });
    });
}

app.use("/user", authorizeServer);
app.get("/user", async function (req, res) {
    console.log("/user");
    const body = req.query;

    const inputCheckPassed = inputCheck(res, [
        typeof (body.bearer) !== "string",
        "Bearer Parameter is required"
    ]);
    if (inputCheckPassed) {
        return;
    }

    let data = (await pool.query(queries.selectUserLogin, [hash(body.bearer)])).rows[0];
    if (!data) {
        sendBadRequest(res, "Account not found");
        return;
    }

    data = (await pool.query(queries.selectUser, [data.users_id])).rows[0];

    const id = data.id;
    const name = data.name;
    const email = data.email;
    const last_login = data.last_login;

    data = (await pool.query(queries.selectUserRoles, [id])).rows.map(({ role }) => role);

    send(res, { id: id, name: name, email: email, last_login: last_login, roles: data });
});

app.use(async (req, res, next) => { await rateLimit(req, res, "global", OPTIONS.RATELIMIT_GLOBAL_LIMIT, OPTIONS.RATELIMIT_GLOBAL_WINDOW, next) });
app.get("/redirect", async function (req, res) {
    console.log("/redirect");
    const body = req.query;
    const cookies = req.cookies;
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    const inputCheckPassed = inputCheck(res, [
        typeof (body.url) !== "string",
        "URL Parameter is required",
        !isAllowedRedirectURL(body.url),
        "Invalid Redirect URL"
    ]);
    if (inputCheckPassed) {
        return;
    }

    let bearer, userAgent = parser(req.headers["user-agent"]), device = userAgent.device.model || userAgent.os.name, devices_id;
    if (cookies.bearer) {
        console.log("Old");

        if (await rateLimitCheck(req, res, "wrongBearerClient", OPTIONS.RATELIMIT_WRONG_BEARER_CLIENT_LIMIT)) {
            return;
        }

        bearer = cookies.bearer;

        const data = (await pool.query(queries.selectUserLogin, [hash(bearer)])).rows[0];
        if (!data) {
            await rateLimitIncrease(req, res, "wrongBearerClient", OPTIONS.RATELIMIT_WRONG_BEARER_CLIENT_LIMIT, RATELIMIT_WRONG_BEARER_CLIENT_WINDOW);
            sendUnauthorized(res, "Unauthorized");
            return;
        }
        await pool.query(queries.updateUsersLastLogin, [data.users_id]);
        devices_id = await insertDevice(device);
        await pool.query(queries.updateUsersLoginsLastLogin, [data.id, ip, devices_id]);
    } else {
        console.log("New");
        const rateLimited = await rateLimit(req, res, "newAccount", OPTIONS.RATELIMIT_NEW_ACCOUNT_LIMIT, OPTIONS.RATELIMIT_NEW_ACCOUNT_WINDOW);
        if (rateLimited) {
            return;
        }

        let name;
        do {
            name = `Guest-${generateToken(5)}`;
        } while ((await pool.query(queries.checkUserName, [name])).rows[0]);

        const id = (await pool.query(queries.insertUser, [name, generateToken(parseInt(Math.random() * 25 + 1))])).rows[0].id;

        let hashedBearer;
        do {
            bearer = generateToken(256);
            hashedBearer = hash(bearer);
        } while ((await pool.query(queries.checkBearer, [hashedBearer])).rows[0]);

        devices_id = await insertDevice(device);
        await pool.query(queries.insertUserLogin, [id, hashedBearer, ip, devices_id]);
    }
    res.cookie("bearer", bearer, { maxAge: 1000 * 60 * 60 * 24 * 365, httpOnly: true, secure: true });

    const url = new URL(body.url);
    const params = new URLSearchParams(url.search);
    params.set("bearer", bearer);
    res.redirect(`${url.origin}${url.pathname}?${params.toString()}`);
});

app.use("/me", authorizeClient);
app.get("/me", async function (req, res) {
    console.log("/me");

    data = (await pool.query(queries.selectUserRoles, [req.user.id])).rows.map(({ role }) => role);

    const picImg = createAvatar(style, { seed: req.user.pic });
    send(res, { name: req.user.name, email: req.user.email, email_confirmed: req.user.email_confirmed, otp_confirmed: req.user.otp_confirmed, pic: picImg, last_login: req.user.last_login, guest: req.user.guest, roles: data });
});

app.use("/me/claim", authorizeClient);
app.post("/me/claim", async function (req, res) {
    console.log("/me/claim");
    const body = req.body;

    const inputCheckPassed = inputCheck(res, [
        typeof (body.name) !== "string",
        "Name Parameter is required",
        body.name.length < 3 || body.name.length > 25,
        "Name must be between 3 and 25 characters long",
        !body.name.toLowerCase().match(/^[\w-_äüöß]+$/i),
        "Name may only contain alphanumeric values, - and _",
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        !req.user.guest,
        "Account already claimed"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if ((await pool.query(queries.checkUserName, [body.name])).rows[0]) {
        sendBadRequest(res, "Name is already taken");
        return;
    }

    const password = await bcrypt.hash(body.password, 10);

    await pool.query(queries.updateUserName, [body.name, req.user.id]);
    await pool.query(queries.updateUserPassword, [password, req.user.id]);

    send(res);
});

// Wyldes Pic: MbA0CfpUxAVXdv580
app.use("/me/changePic", authorizeClient);
app.post("/me/changePic", async function (req, res) {
    console.log("/me/changePic");
    const body = req.body;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if (! await bcrypt.compare(body.password, req.user.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    await pool.query(queries.updateUserPic, [generateToken(parseInt(Math.random() * 25 + 1)), req.user.id]);

    res.redirect("/me");
});

app.use("/me/changeName", authorizeClient);
app.post("/me/changeName", async function (req, res) {
    console.log("/me/changeName");
    const body = req.body;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    if (await rateLimitCheck(req, res, "changeName", OPTIONS.RATELIMIT_CHANGE_NAME_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        typeof (body.name) !== "string",
        "Name Parameter is required",
        body.name.length < 3 || body.name.length > 25,
        "Name must be between 3 and 25 characters long",
        !body.name.toLowerCase().match(/^[\w-_äüöß]+$/i),
        "Name may only contain alphanumeric values, - and _",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if (! await bcrypt.compare(body.password, req.user.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    if ((await pool.query(queries.checkUserName, [body.name])).rows[0]) {
        sendBadRequest(res, "Name is already taken");
        return;
    }

    await rateLimitIncrease(req, res, "changeName", OPTIONS.RATELIMIT_CHANGE_NAME_LIMIT, OPTIONS.RATELIMIT_CHANGE_NAME_WINDOW);

    await pool.query(queries.updateUserName, [body.name, req.user.id]);

    res.redirect("/me");
});

app.use("/me/changePassword", authorizeClient);
app.post("/me/changePassword", async function (req, res) {
    console.log("/me/changePassword");
    const body = req.body;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        typeof (body.newPassword) !== "string",
        "newPassword Parameter is required",
        body.newPassword.length < 6 || body.newPassword.length > 256,
        "newPassword must be between 6 and 256 characters long",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if (! await bcrypt.compare(body.password, req.user.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    const password = await bcrypt.hash(body.newPassword, 10);
    await pool.query(queries.updateUserPassword, [password, req.user.id]);

    send(res);
});

app.use("/me/enableEmail", authorizeClient);
app.post("/me/enableEmail", async function (req, res) {
    console.log("/me/enableEmail");
    const body = req.body;
    const email = addrs.parseOneAddress(body.email);

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    if (await rateLimitCheck(req, res, "changeEmail", OPTIONS.RATELIMIT_CHANGE_EMAIL_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        typeof (body.email) !== "string",
        "Email Parameter is required",
        body.email.length > 50,
        "Email must not be longer than 50 characters",
        !email,
        "Email must be valid",
        req.user.email,
        "Email already enabled",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if (! await bcrypt.compare(body.password, req.user.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    if ((await pool.query(queries.checkUserEmail, [email.address])).rows[0]) {
        sendBadRequest(res, "Email is already taken");
        return;
    }

    const email_token = generateToken(25);

    await rateLimitIncrease(req, res, "changeEmail", OPTIONS.RATELIMIT_CHANGE_EMAIL_LIMIT, OPTIONS.RATELIMIT_CHANGE_EMAIL_WINDOW);
    await pool.query(queries.unconfirmUserEmail, [email.address, email_token, req.user.id]);

    mail(email.address, "MultiAuth: Activate Your Account", `Hi ${req.user.name}!\nWelcome to MultiAuth: The SSO(Single Sign On) Authentification Portal for other services\n\nPlease confirm your MultiAuth Email here: ${encodeURI(OPTIONS.URL + "/confirmEmail?email=" + email.address + "&token=" + email_token)}\n\n\nThe MultiAuth Team`);

    res.redirect("/me");
});

app.use("/me/disableEmail", authorizeClient);
app.post("/me/disableEmail", async function (req, res) {
    console.log("/me/disableEmail");
    const body = req.body;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        !req.user.email,
        "Email not enabled",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if (! await bcrypt.compare(body.password, req.user.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    await pool.query(queries.disableUserEmail, [req.user.id]);

    res.redirect("/me");
});

app.get("/confirmEmail", async function (req, res) {
    console.log("/confirmEmail");
    const body = req.query;
    const email = addrs.parseOneAddress(body.email);

    if (await rateLimitCheck(req, res, "wrongEmailConfirm", OPTIONS.RATELIMIT_WRONG_EMAIL_CONFIRM_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.email) !== "string",
        "Email Parameter is required",
        body.email.length > 50,
        "Email must not be longer than 50 characters",
        !email,
        "Email must be valid",
        typeof (body.token) !== "string",
        "Token Parameter is required",
        body.token.length != 25,
        "Token must be 25 characters long"
    ]);
    if (inputCheckPassed) {
        return;
    }

    let data = (await pool.query(queries.checkConfirmUserEmail, [email.address, body.token])).rows[0];
    if (!data) {
        await rateLimitIncrease(req, res, "wrongEmailConfirm", OPTIONS.RATELIMIT_WRONG_EMAIL_CONFIRM_LIMIT, OPTIONS.RATELIMIT_WRONG_EMAIL_CONFIRM_WINDOW);
        sendBadRequest(res, "No email to confirm");
        return;
    }

    await pool.query(queries.confirmUserEmail, [data.id]);

    res.redirect("/redirect?url=" + encodeURI(OPTIONS.FRONTEND_URL + "/account"));
});

app.use("/me/enableOTP", authorizeClient);
app.post("/me/enableOTP", async function (req, res) {
    console.log("/me/enableOTP");

    const inputCheckPassed = inputCheck(res, [
        req.user.otp_confirmed,
        "OTP already enabled",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    const { base32, otpauth_url } = speakeasy.generateSecret({ length: 8 });

    const img = await QRCode.toDataURL(otpauth_url);

    await pool.query(queries.unconfirmUserOTP, [base32, req.user.id]);
    send(res, { otp: base32, img: img });
});

app.use("/me/confirmOTP", authorizeClient);
app.post("/me/confirmOTP", async function (req, res) {
    console.log("/me/confirmOTP");
    const body = req.body;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    if (await rateLimitCheck(req, res, "wrongTOTP", OPTIONS.RATELIMIT_WRONG_TOTP_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        typeof (body.totp) !== "string",
        "TOTP Parameter is required",
        body.totp.length != 6,
        "TOTP must be 6 characters long",
        req.user.otp_confirmed,
        "OTP already enabled",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if (! await bcrypt.compare(body.password, req.user.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    const verified = speakeasy.totp.verify({
        secret: req.user.otp,
        encoding: "base32",
        token: body.totp,
        window: 6
    });

    if (!verified) {
        await rateLimitIncrease(req, res, "wrongTOTP", OPTIONS.RATELIMIT_WRONG_TOTP_LIMIT, OPTIONS.RATELIMIT_WRONG_TOTP_WINDOW);
        sendBadRequest(res, "Wrong TOTP");
        return;
    }

    await pool.query(queries.confirmUserOTP, [req.user.otp, req.user.id]);
    res.redirect("/me");
});

app.use("/me/disableOTP", authorizeClient);
app.post("/me/disableOTP", async function (req, res) {
    console.log("/me/disableOTP");
    const body = req.body;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        !req.user.otp_confirmed,
        "OTP not enabled",
        req.user.guest,
        "Account must be claimed first"
    ]);
    if (inputCheckPassed) {
        return;
    }

    if (! await bcrypt.compare(body.password, req.user.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    await pool.query(queries.disableUserOTP, [req.user.id]);

    res.redirect("/me");
});

app.get("/logout", async function (req, res) {
    console.log("/logout");
    const cookies = req.cookies;

    if (await rateLimitCheck(req, res, "wrongBearerClient", OPTIONS.RATELIMIT_WRONG_BEARER_CLIENT_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (cookies.bearer) !== "string",
        "Bearer Parameter is required",
        cookies.bearer.length != 256,
        "Bearer must be 256 characters long",
    ]);
    if (inputCheckPassed) {
        return;
    }

    const data = (await pool.query(queries.selectUserLogin, [hash(cookies.bearer)])).rows[0];
    if (!data) {
        await rateLimitIncrease(req, res, "wrongBearerClient", OPTIONS.RATELIMIT_WRONG_BEARER_CLIENT_LIMIT, RATELIMIT_WRONG_BEARER_CLIENT_WINDOW);
        sendUnauthorized(res, "Unauthorized");
        return;
    }

    await pool.query(queries.deleteBearer, [data.id]);

    res.clearCookie("bearer");
    res.redirect("/redirect?url=" + encodeURI(OPTIONS.FRONTEND_URL));
});

app.post("/checkOTP", async function (req, res) {
    console.log("/checkOTP");
    const body = req.body;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    if (await rateLimitCheck(req, res, "wrongName", OPTIONS.RATELIMIT_WRONG_NAME_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        typeof (body.name) !== "string",
        "Name Parameter is required",
        body.name.length < 3 || body.name.length > 25,
        "Name must be between 3 and 25 characters long",
        !body.name.toLowerCase().match(/^[\w-_äüöß]+$/i),
        "Name may only contain alphanumeric values, - and _",
    ]);
    if (inputCheckPassed) {
        return;
    }

    let data = (await pool.query(queries.checkUserName, [body.name])).rows[0];

    if (!data) {
        await rateLimitIncrease(req, res, "wrongName", OPTIONS.RATELIMIT_WRONG_NAME_LIMIT, OPTIONS.RATELIMIT_WRONG_NAME_WINDOW);
        sendBadRequest(res, "Account not found");
        return;
    }

    if (!data.password) {
        sendBadRequest(res, "Account must be claimed first");
        return;
    }

    if (! await bcrypt.compare(body.password, data.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    send(res, { otp_confirmed: data.otp_confirmed });
});

app.get("/login", async function (req, res) {
    console.log("/login");
    const body = req.query;
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    if (await rateLimitCheck(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT)) {
        return;
    }

    if (await rateLimitCheck(req, res, "wrongName", OPTIONS.RATELIMIT_WRONG_NAME_LIMIT)) {
        return;
    }

    if (await rateLimitCheck(req, res, "wrongTOTP", OPTIONS.RATELIMIT_WRONG_TOTP_LIMIT)) {
        return;
    }

    const inputCheckPassed = inputCheck(res, [
        typeof (body.password) !== "string",
        "Password Parameter is required",
        body.password.length < 6 || body.password.length > 256,
        "Password must be between 6 and 256 characters long",
        typeof (body.name) !== "string",
        "Name Parameter is required",
        body.name.length < 3 || body.name.length > 25,
        "Name must be between 3 and 25 characters long",
        !body.name.toLowerCase().match(/^[\w-_äüöß]+$/i),
        "Name may only contain alphanumeric values, - and _",
        isSet(body.totp) && typeof (body.totp) !== "string",
        "TOTP Parameter is required",
        isSet(body.totp) && body.totp.length != 6,
        "TOTP must be 6 characters long",
    ]);
    if (inputCheckPassed) {
        return;
    }

    const data = (await pool.query(queries.checkUserName, [body.name])).rows[0];

    if (!data) {
        await rateLimitIncrease(req, res, "wrongName", OPTIONS.RATELIMIT_WRONG_NAME_LIMIT, OPTIONS.RATELIMIT_WRONG_NAME_WINDOW);
        sendBadRequest(res, "Account not found");
        return;
    }

    if (!data.password) {
        sendBadRequest(res, "Account must be claimed first");
        return;
    }

    if (! await bcrypt.compare(body.password, data.password)) {
        await rateLimitIncrease(req, res, "wrongPassword", OPTIONS.RATELIMIT_WRONG_PASSWORD_LIMIT, OPTIONS.RATELIMIT_WRONG_PASSWORD_WINDOW);
        sendBadRequest(res, "Wrong password");
        return;
    }

    if (data.otp_confirmed) {
        const verified = speakeasy.totp.verify({
            secret: data.otp,
            encoding: "base32",
            token: body.totp,
            window: 6
        });

        if (!verified) {
            await rateLimitIncrease(req, res, "wrongTOTP", OPTIONS.RATELIMIT_WRONG_TOTP_LIMIT, OPTIONS.RATELIMIT_WRONG_TOTP_WINDOW);
            sendBadRequest(res, "Wrong TOTP");
            return;
        }
    }

    let bearer, hashedBearer, userAgent = parser(req.headers["user-agent"]), device = userAgent.device.model || userAgent.os.name, devices_id;
    do {
        bearer = generateToken(256);
        hashedBearer = hash(bearer);
    } while ((await pool.query(queries.checkBearer, [hashedBearer])).rows[0]);

    devices_id = await insertDevice(device);
    await pool.query(queries.insertUserLogin, [data.id, hashedBearer, ip, devices_id]);
    res.cookie("bearer", bearer, { maxAge: 1000 * 60 * 60 * 24 * 365, httpOnly: true, secure: true });

    res.redirect("/redirect?url=" + encodeURI(OPTIONS.FRONTEND_URL));
});

if (OPTIONS.HTTPS === "true") {
    https.createServer({
        key: fs.readFileSync(OPTIONS.CERT_PRIV),
        cert: fs.readFileSync(OPTIONS.CERT_PUB),
        ca: fs.readFileSync(OPTIONS.CERT_CA),
    }, app)
        .listen(OPTIONS.PORT, OPTIONS.HOSTNAME, () => {
            console.log(`MultiAuth Backend listening at ${OPTIONS.URL}`);
        });
} else {
    app.listen(OPTIONS.PORT, OPTIONS.HOSTNAME, () => {
        console.log(`MultiAuth Backend listening at ${OPTIONS.URL}`);
    });
}
