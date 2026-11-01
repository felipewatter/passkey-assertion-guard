# Changelog

## [0.1.0] — 2026-11-01

- Implementado verificador de assertions WebAuthn com assinatura ES256 (P-256) e Ed25519.
- Verificadas identidade de credencial, origem HTTPS, RP ID, challenge, UP/UV e flags de backup.
- Estado de demonstração em memória com challenge de 256 bits, TTL, consumo único e revogação de credencial.
- Regras para contador WebAuthn, incluindo caso legítimo de contador zero.
- Rejeição de JSON ambíguo, chaves públicas privadas ou algoritmos inesperados, base64url inválido e formatos não suportados.
- Testes de regressão locais, CI multiplataforma Node 22/24, documentação de arquitetura e modelo de ameaças.

**Aviso:** não implementa registro, attestation ou armazenamento distribuído. Não é uma solução pronta para autenticação em produção.
