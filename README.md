# Network Analyzer

This is a hobby project of mine, it uses encoding models to spot outliers / suspicious network traffic

## Stack / Makeup
- Fastapi backend
- Vite & React frontend
- Nginx to serve vite frontend
- Docker to package these all togtether and easily package with pgvector for quick local setup

## Changelog
### v0.2.0
- File uploading in api and frontend with docker volume to persist uploads
- Docker compose wrote to help containers communicate and include pgvector
- API contains upload and list endpoint for logs
- Nginx proxy used to fix CORS issues with cookies
- Drivers and ORM included in api for future db intergration, although no code with drivers actually implemented yet
- Changelog added to README.md
### v0.1.0
- Basic boilerplate
- Basic modal for login and basic login logic on backend (just uses a simple app password hash and cookies)
