# Relatório de validação local — Passkey Assertion Guard 0.1.0

## Testes e ferramentas

- `npm run check`: PASS (JavaScript sintaticamente válido).
- `npm test`: **51 testes automatizados aprovados** (sem falhas, sem ignorados).
- `npm run demo`: PASS (ES256 válido, replay recusado, signatário não registrado recusado).
- `npm audit --audit-level=high`: 0 vulnerabilidades reportadas; pacote sem dependências de execução.
- `npm pack --dry-run --ignore-scripts`: verificar antes de distribuir.

## Cenários cobertos

Assinaturas ES256 e Ed25519, alteração de bytes, challenge errado/expirado/consumido, chave de outra credencial, ID errado, domínio/RP diferente, crossOrigin, flags UP/UV, backup eligibility/state, contador zero/monotonicidade, rejeição de dados extra, JSON com chaves duplicadas, base64url canônico, limites de entrada, cópia de estado e revogação.

## O que ainda não foi testado

- Matriz GitHub Actions Ubuntu/Windows/macOS e Node.js 22/24, que só pode rodar após criar o repositório.
- Integração com navegador real, registro WebAuthn, attestation de hardware, armazenamento multi-instância, banco transacional e autenticação HTTP de produção.
- Auditoria criptográfica externa independente.

**O projeto não deve ser usado como substituto de uma solução WebAuthn completa e auditada.**