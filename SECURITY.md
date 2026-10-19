# Security policy

## Reporting a vulnerability
Please open a private security advisory on GitHub (Security tab -> Report a vulnerability) or email sriramojunikhil66@gmail.com.
Do not open public issues for vulnerabilities. Expect an acknowledgement within 72 hours.

## Scope and honesty
SecureNav-NEXUS is a research and portfolio platform. It is **not** a certified safety or security product.
The HSM is an emulator (use a TPM / PKCS#11 device in production). The default vision weights are untrained until you run
`vision.train_vision` or supply your own. Never deploy against real vehicles without independent safety validation.

## Secrets
Never commit keys. `keystore/`, `secrets/`, `*.vault` and model artifacts are git-ignored. Groq keys belong in
`secrets/groq_api_key.txt` (server) or the browser's localStorage (demo site), and should be revocable.

## Supported versions
Only the latest 2.x release receives fixes.
