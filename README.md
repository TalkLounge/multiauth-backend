# MultiAuth Backend
Simple Single Sign On for your website project
<br>
Have you ever been annoyed by user authentication when programming a website? Use MultiAuth
<br>
See [MultiAuth Frontend](https://github.com/TalkLounge/multiauth-frontend#readme) for more detailed information

## Table of Contents
- [MultiAuth Backend](#multiauth-backend)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Getting Started](#getting-started)
    - [Requirements](#requirements)
    - [Installation](#installation)
  - [Usage](#usage)
    - [With Your Frontend](#with-your-frontend)
    - [With Your Backend](#with-your-backend)
  - [License](#license)

## Features
* Server side rendering for better SEO
* Customizable rate limiting against brute force attacks
* See more features in the [MultiAuth Frontend](https://github.com/TalkLounge/multiauth-frontend#features)

## Getting Started
Consider installing the [MultiAuth Frontend](https://github.com/TalkLounge/multiauth-frontend) first!

### Requirements
* [Node.js](https://nodejs.org/)
* [Postgres](https://www.postgresql.org/)
* [Redis](https://redis.io/)
* [Mailutils](https://mailutils.org/)

### Installation
```
git clone https://github.com/TalkLounge/multiauth-backend
cd multiauth-backend
npm install
```
* Copy [.env.example](.env.example) to [.env](.env)
<br>
* Configure [.env](.env)
* Create postgres database based on [.env](.env) POSTGRES_DATABASE
```
npm start
```

## Usage
Explains how your website project can use MultiAuth as SSO Provider
<br>
See [MultiDL Frontend](https://github.com/TalkLounge/multidl-frontend) and [MultiDL Backend](https://github.com/TalkLounge/multidl-backend) as an example integration

### With Your Frontend
* Add your frontend url to [.env](.env) REDIRECT_URLS
* Add your roles to [.env](.env) ROLES
* On page load
    * Redirect the user to http[s]://YOUR_MULTIAUTH_BACKEND/redirect?back=YOUR_CURRENT_WEBSITE_ROUTE
    * MultiAuth Backend will create a new guest account or use the current account
    * MultiAuth Backend will redirect to YOUR_CURRENT_WEBSITE_ROUTE?bearer=BEARER
    * Read, save and then delete the bearer from the url
    * Load more user data from GET http[s]://YOUR_MULTIAUTH_BACKEND/me HEADERS Authorization: Bearer BEARER
* Consider showing profile picture in navbar and on click redirect to http[s]://YOUR_MULTIAUTH_FRONTEND/?back=YOUR_CURRENT_WEBSITE_ROUTE

### With Your Backend
* Add your backend bearer to [.env](.env) BEARERS
* Add your roles to [.env](.env) ROLES
* Validate User Bearer
    * Load user data from GET http[s]://YOUR_MULTIAUTH_BACKEND/user HEADERS Authorization: Bearer BACKEND_BEARER QUERY bearer=USER_BEARER
    * Rate Limit this request! A user should not be able to brute force USER_BEARER through your backend due your backend will not be rate limited as long the BACKEND_BEARER is correct.
    * Wrong USER_BEARER will respond in 400 Account not found

## License
MIT