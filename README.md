<div align="center">
  <img src="https://assets.s3.jdbnet.co.uk/logo/200x200.png" alt="JDB-NET" width="200" />
  
  # JDB-NET SSH

A modern, browser-based SSH workspace for managing remote access in one place.

</div>

JDB-NET SSH gives you a clean web interface for opening secure shell sessions, organising hosts, and transferring files over SFTP without juggling multiple desktop tools. It is built for day-to-day server access with a fast tabbed terminal experience, reusable connection identities, and straightforward navigation for both occasional and frequent use.

## Features

- Secure sign-in before accessing hosts and sessions
- Tabbed SSH terminal sessions for working on multiple servers at once
- Support for password and SSH key authentication (including passphrase-protected keys)
- Jump host support for reaching internal systems through bastion hosts
- Built-in SFTP browser with upload, download, rename, delete, and folder creation actions
- Searchable and organised host navigation to find connections quickly
- Connection history visibility to review recent activity and session duration

## Docker Compose

```yaml
services:
  app:
    image: cr.jdbnet.co.uk/public/ssh:latest
    ports:
      - "5000:5000"
    environment:
      GEVENT_MONKEY_PATCH: "1"
      MYSQL_HOST: "<YOUR_MYSQL_HOST>"
      MYSQL_DATABASE: "<YOUR_MYSQL_DATABASE>"
      MYSQL_USER: "<YOUR_MYSQL_USER>"
      MYSQL_PASSWORD: "<YOUR_MYSQL_PASSWORD>"
      SESSION_COOKIE_SECURE: "true"
      WEBAPP_USERNAME: "<YOUR_WEBAPP_USERNAME>"
      WEBAPP_PASSWORD: "<YOUR_WEBAPP_PASSWORD>"
      SECRET_KEY: "<YOUR_SECRET_KEY>"
      CREDENTIALS_ENCRYPTION_KEY: "<YOUR_CREDENTIALS_ENCRYPTION_KEY>"
    restart: unless-stopped
```