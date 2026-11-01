# Modelo de ameaças — v0.1.0

## Objetivo

Verificar a validade criptográfica de uma assertion de autenticação WebAuthn em um perfil explícito e limitado. Não avaliar a segurança física de um autenticador e não implementar registro ou login de ponta a ponta.

## Controles e limitações

| Ameaça | Controle implementado | Risco residual |
|---|---|---|
| Replay de challenge | Emissão 256-bit, TTL e consumo único em `CeremonyStore` | Estado somente em memória; exige store transacional distribuído |
| Assinatura por chave desconhecida | Chaves JWK confiáveis fornecidas pelo registro anterior | Cadastro WebAuthn não implementado |
| Uso de desafio de outra sessão | Desafio associado a credencial e comparação de bytes | Atribuição à conta/sessão HTTP deve ser fornecida pela aplicação |
| Phishing por origin divergente | Comparação exata do origin e RP ID hash | Perfil restrito não suporta origens legítimas múltiplas |
| Usuário não presente ou UV exigido ausente | Bits UP/UV verificados | Flags dependem do autenticador e da confiança no registro |
| Clonagem com contador repetido | Rejeição de contador que não avance | Authenticator com contador 0 não oferece esta detecção |
| Backup state inesperado | Validação BE/BS e política de permissividade | Sincronização legítima de passkeys pode alterar BS |
| JSON ambíguo e algoritmos inseguros | Parser estrito, flags desconhecidas rejeitadas, apenas ES256/Ed25519 | Versões futuras de WebAuthn exigem novos formatos explicitamente auditados |
| Exaustão de recursos | Limites de blobs, desafios em memória, tentativas por desafio | Rate limiting HTTP externo, limites globais e ciclos de vida ainda necessários |
| Comprometimento do backend | Não protegido por biblioteca | Segredos, políticas e estado do servidor podem ser alterados |

## Não objetivos

- Registro e verificação de attestation FIDO2, CTAP2, sincronização de passkeys e análise de metadados FIDO Alliance.
- Gerenciamento de usuários, cookies, anti-CSRF, sessões HTTP, OAuth/OIDC e Web APIs do navegador.
- Auditoria de hardware do autenticador ou conformidade formal WebAuthn/FIDO.
- Proteção contra replay entre múltiplas instâncias (sem adapter externo transacional).

## Testes adversariais

A suíte automatizada inclui adulteração de assinaturas e payload, desafio inválido/expirado, troca de origin/RP, flags incompatíveis, mudança de contador, credencial não confiável, JSON com chaves duplicadas e replay.