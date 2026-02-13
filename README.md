# OAuth Registration Plugin for CTFd

This CTFd plugin enables **Google OAuth-based user registration**.

---

## Features

- Google OAuth 2.0 registration flow
- Automatically creates a CTFd user with:
  - Google name  
  - Google email  
  - Random strong password  
- Prevents users from changing their email

## Note before you use this

- The plugin DOES NOT check email domains when registering. If you are hosting a private CTF, make sure you keep your oauth client private when registering it on Google Cloud. That should be enough.

---

## Installation
1. Place this plugin directory inside:
```
CTFd/CTFd/plugins/oauth/
```
2. Ensure the plugin contains:
```
.
├── client_secrets.json
├── __init__.py
├── README.md
├── requirements.txt
└── templates
    └── register_oauth.html

2 directories, 5 files
```
3. Your `client_secrets.json` should be obtained from Google Cloud Console and placed next to `__init__.py`.
4. Set this environment variable:
```
REDIRECT_URI=https://your-ctfd-domain/register
```
This must match the redirect URI you configured in Google OAuth.
5. Restart CTFd.
6. Go to the `/register` endpoint, and you should see a `Login with Google` button.