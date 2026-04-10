# Network Analyzer

This is a hobby project of mine, it uses encoding models to spot outliers / suspicious network traffic

## Stack / Makeup
- Fastapi backend
- Vite & React frontend
- Nginx to serve vite frontend
- Docker to package these all togtether and easily package with pgvector for quick local setup

## Changelog
### v0.5.0
- Interactive t-SNE 2D map showing distance between network sections
- Anomaly detection via Local Outlier Factor with color-coded severity (green/amber/red)
- Clickable map sections display packet ranges and detailed statistics
- Configurable upload processing: choose batch count or timeframe per file
- Support for large file uploads (up to 500MB)
- Auto-authentication on page load if session token exists
- Parallel pcap-to-csv conversion for faster processing
### v0.4.0
- Uses unique filename saving to avoid conflicts
- Work started on python ORM for the pgvector database
- Validation for uploaded logs
- Got database models working
- Got embedding generation working
- Make schema.sql for adding extension
- Added demoenv
- Created async version of natural language gen functions
### v0.3.0
- Started work on workflow to turn a client's .pcap files into natural language ready for embedding models
- Switched OpenAI key varibles to OpenRouter
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

## TODOs / Ideas
- To be able to show the "distances" between captures in a visual format, currently thinking of implementing t-SNE to represent this in a 2D format [JS implementation / Library](https://cs.stanford.edu/people/karpathy/tsnejs)
