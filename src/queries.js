module.exports = {
    init: {
        createTableUsers:
            `CREATE TABLE IF NOT EXISTS users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name VARCHAR(25) UNIQUE NOT NULL,
                password VARCHAR(60),
                password_token VARCHAR(25),
                password_token_expire TIMESTAMP,
                email VARCHAR(50),
                email_confirmed BOOL NOT NULL DEFAULT FALSE,
                email_token VARCHAR(25),
                email_token_expire TIMESTAMP,
                otp VARCHAR(52),
                otp_confirmed BOOL NOT NULL DEFAULT FALSE,
                pic VARCHAR(25) NOT NULL,
                last_login TIMESTAMP NOT NULL DEFAULT now()
            );`,
        createTableUsersLogins:
            `CREATE TABLE IF NOT EXISTS users_logins (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                users_id BIGINT NOT NULL,
                bearer VARCHAR(64) UNIQUE,
                ip INET NOT NULL,
                devices_id INT,
                last_login TIMESTAMP NOT NULL DEFAULT now()
            );`,
        createTableDevices:
            `CREATE TABLE IF NOT EXISTS devices (
                id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                device VARCHAR(25) UNIQUE NOT NULL
            );`,
        createTableRoles:
            `CREATE TABLE IF NOT EXISTS roles (
                id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                role VARCHAR(25) UNIQUE
            );`,
        createTableUsersRoles:
            `CREATE TABLE IF NOT EXISTS users_roles (
                users_id BIGINT NOT NULL,
                roles_id INT NOT NULL,
                PRIMARY KEY(users_id, roles_id)
            );`,
    },
    insertRole: `INSERT INTO roles (role) VALUES ($1) ON CONFLICT DO NOTHING`,
    checkUserName: `SELECT id, password, otp, otp_confirmed FROM users WHERE LOWER(name) = LOWER($1)`,
    insertUser: `INSERT INTO users (name, pic) VALUES ($1, $2) RETURNING id`,
    checkBearer: `SELECT id FROM users_logins WHERE bearer = $1`,
    selectDevice: `SELECT id FROM devices WHERE device = $1`,
    insertDevice: `INSERT INTO devices (device) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id`,
    insertUserLogin: `INSERT INTO users_logins (users_id, bearer, ip, devices_id) VALUES ($1, $2, $3, $4)`,
    selectUserLogin: `SELECT * FROM users_logins WHERE bearer = $1`,
    updateUsersLastLogin: `UPDATE users SET last_login = now() WHERE id = $1`,
    updateUsersLoginsLastLogin: `UPDATE users_logins SET last_login = now(), ip = $2, devices_id = $3 WHERE id = $1`,
    selectUser: `SELECT *, password IS NULL as guest FROM users WHERE id = $1`,
    selectUserRoles: `SELECT role FROM users_roles INNER JOIN roles ON roles_id = id WHERE users_id = $1`,
    insertUserRole: `INSERT INTO users_roles (users_id, roles_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    updateUserName: `UPDATE users SET name = $1 WHERE id = $2`,
    updateUserPassword: `UPDATE users SET password = $1 WHERE id = $2`,
    updateUserPic: `UPDATE users SET pic = $1 WHERE id = $2`,
    checkUserEmail: `SELECT id FROM users WHERE LOWER(email) = LOWER($1)`,
    unconfirmUserEmail: `UPDATE users SET email_confirmed = FALSE, email = $1, email_token = $2, email_token_expire = now() + interval '1 day' WHERE id = $3`,
    disableUserEmail: `UPDATE users SET email_confirmed = FALSE, email = NULL, email_token = NULL, email_token_expire = NULL WHERE id = $1`,
    checkConfirmUserEmail: `SELECT id FROM users WHERE email_confirmed = FALSE AND email = $1 AND email_token = $2`,
    confirmUserEmail: `UPDATE users SET email_confirmed = TRUE, email_token = NULL, email_token_expire = NULL WHERE id = $1`,
    unconfirmUserOTP: `UPDATE users SET otp_confirmed = FALSE, otp = $1 WHERE id = $2`,
    confirmUserOTP: `UPDATE users SET otp_confirmed = TRUE WHERE otp = $1 AND id = $2`,
    disableUserOTP: `UPDATE users SET otp_confirmed = FALSE, otp = NULL WHERE id = $1`,
    deleteBearer: `DELETE FROM users_logins WHERE id = $1`,
}