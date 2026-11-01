# Arquitetura e implementação

## Componentes

| Arquivo | Finalidade |
|---|---|
| `src/codec.js` | Base64url canônico, limites, SHA-256, checagens de estrutura, origem HTTPS |
| `src/strict-json.js` | Parser JSON com detecção de chaves duplicadas e limite de profundidade/tokens |
| `src/index.js` | Credenciais EC/Ed25519, verificação criptográfica, desafio vinculado à sessão e contador |
| `src/demo.js` | Demonstração efêmera com sucesso, replay recusado e chave não confiável recusada |
| `src/cli.js` | Comandos `demo`, `--help`, `--version` |

## Operação `verifyAssertion`

1. Recebe credencial pública **anteriormente validada** e desafio esperado externamente, além de `origin` fixo pelo servidor.
2. Confere campos do objeto público WebAuthn, `id`/`rawId`, `type`, byte lengths, base64url e payload JSON.
3. Garante `clientDataJSON.type = webauthn.get`, `challenge` igual ao esperado e `origin` exatamente autorizado; rejeita `crossOrigin: true`.
4. Confirma `authenticatorData` de 37 bytes e `rpIdHash` igual a SHA-256 do hostname HTTPS esperado.
5. Exige `UP`, opcionalmente `UV`; valida flags BE/BS e rejeita extensões/flags não suportadas.
6. Compara contadores quando suportados e rejeita não avanço depois de valor diferente de zero.
7. Verifica assinatura ES256 (P-256) ou Ed25519 sobre `authenticatorData || SHA256(clientDataJSON)` usando chave pública confiável.
8. Retorna resultado imutável mínimo; **não consome o challenge** por si só.

## `CeremonyStore`

Em uma única instância Node.js, armazena as credenciais provisionadas, emite challenges aleatórios de 32 bytes, valida o estado de expiração, faz até 5 tentativas associadas a um challenge, consome o challenge após verificação e atualiza o contador em uma seção síncrona.

**Em produção, a aplicação deve substituir `CeremonyStore` por armazenamento transacional confiável.** Não é uma implementação de autenticação distribuída nem substitui as obrigações da especificação WebAuthn.

## Perfil conscientemente restritivo

- ES256 e EdDSA apenas; JWK público sem material privado.
- Origem única HTTPS canônica e RP ID igual ao hostname exato.
- Sem `clientExtensionResults` externos, sem extensões dentro do authData, sem attestation.
- Nenhuma chamada externa ou interpretação de CBOR; as chaves JWK de cadastro vêm do lado servidor.

## Referências

- W3C: https://www.w3.org/TR/webauthn-3/
- MDN: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion
- Google: https://developers.google.com/identity/passkeys/developer-guides/server-authentication