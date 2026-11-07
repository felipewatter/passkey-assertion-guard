# Passkey Assertion Guard

**Verificação defensiva de respostas de autenticação WebAuthn com vinculação criptográfica ao domínio e ao desafio, validação de flags e contadores, e proteção contra reutilização de desafios em um único processo.**

> **v0.1.0 — biblioteca de escopo intencionalmente restrito, experimental e não auditada independentemente.** Não é um servidor WebAuthn completo, não implementa registro de credenciais ou validação de attestation, não oferece sessão de login pronta e não deve ser utilizada isoladamente como sistema de autenticação em produção. Para integração completa prefira bibliotecas maduras como SimpleWebAuthn.

## Problema de segurança

A autenticação por passkeys exige validar muito mais que uma assinatura: a aplicação verificadora precisa confirmar o **challenge emitido pelo servidor**, o **origin esperado**, o hash do **RP ID**, a **presença do usuário (UP)**, eventualmente sua **verificação (UV)**, a chave pública registrada previamente e os contadores de assinatura quando disponíveis. Sem validação desses atributos, fluxos de autenticação podem aceitar respostas inconsistentes com a sessão pretendida.

O **Passkey Assertion Guard** fornece um núcleo de verificação para estudo e testes de integração, sem conectar a um navegador ou banco de dados. É um projeto distinto dos scanners de CVE, JWT, segredo, monitoramento de arquivos e checagem de proveniência de artefatos do portfólio.

## Recursos implementados

| Controle | Status |
|---|---|
| Verificação criptográfica ES256 (P-256 + SHA-256) | Implementada, Node Crypto |
| Verificação criptográfica EdDSA (Ed25519) | Implementada, Node Crypto |
| Assinatura de `authenticatorData || SHA256(clientDataJSON)` | Implementada |
| Validação exata do `type = webauthn.get` e do `origin` | Implementada |
| Vinculação ao hash SHA-256 do RP ID | Implementada (perfil de origem = RP ID) |
| Comparação de challenge com emissão do servidor | Implementada |
| Challenges criptograficamente aleatórios (32 bytes) e temporários | Implementados |
| Consumo único de challenges após autenticação | Implementado para processo único |
| Rejeição de chave não confiável ou identidade de credencial alterada | Implementada |
| Regras UP/UV, flags reservadas, backup eligibility/state | Implementadas |
| Controle de avanço de `signCount` quando disponível | Implementado |
| Bloqueio de excesso de tentativas por challenge | Implementado (5 tentativas por challenge conhecido) |
| Revogação de credencial na memória | Implementada |
| JSON estrito e base64url canônico com limites de leitura | Implementados |
| Testes adversariais e demonstração reproduzível | Incluídos |
| Suporte a registro e attestation WebAuthn | **Não implementado** |
| Armazenamento persistente/múltiplas instâncias | **Não implementado** |
| REST API e login com sessão | **Não implementados** |

## Arquitetura

```text
Credencial pré-registrada e confiável         Browser / autenticador
             |                                          |
  PublicKey JWK + credentialId                         |
             |                                   authenticatorData
  CeremonyStore em memória                   + clientDataJSON + signature
       issueChallenge()                                 |
             |                                          |
       challenge 256 bits ------------------------------>| 
             |                                          |
             +----------- verifyAssertion() <-----------+
                              |
        origin / RP ID / challenge / flags / signCount
                              |
                      Ed25519 ou ES256
                              |
              aceitar e consumir challenge UMA vez
                              |
                     estado de contador atualizado
```

**A chave pública deve ser fornecida por um fluxo de registro previamente autenticado e validado**, fora deste projeto. Não aceite uma chave pública apresentada pela própria assertion.

## Instalação

Requer Node.js **22 ou 24**; **nenhuma dependência de runtime externa**.

```bash
git clone https://github.com/felipewatter/passkey-assertion-guard.git
cd passkey-assertion-guard
npm ci --ignore-scripts
npm run check
npm test
npm run demo
```

Também pode executar a demonstração sem instalação prévia:

```bash
node src/cli.js demo
```

A demonstração usa um autenticador **simulado localmente**, com chaves descartáveis, para validar assinatura, challenge único e rejeição de uma chave diferente. **Não cria uma passkey real.**

## Exemplo mínimo

```javascript
import { CeremonyStore } from './src/index.js';

const store = new CeremonyStore({
  origin: 'https://login.example.org',
  requireUserVerification: true,
  allowBackup: true,
});

// Credencial fornecida por um registro WebAuthn externo previamente verificado.
store.enrollTrustedCredential({
  id: '<BASE64URL_CREDENTIAL_ID>',
  publicKeyJwk: { kty: 'EC', crv: 'P-256', x: '<X>', y: '<Y>' },
  signCount: 0,
  backupEligible: false,
});

// Etapa 1 — gerar desafio para uma tentativa de autenticação.
const challenge = store.issueChallenge('<BASE64URL_CREDENTIAL_ID>');

// Etapa 2 — fornecer challenge em PublicKeyCredentialRequestOptions no navegador.
// Etapa 3 — receber assertion serializada do navegador em backend autenticado.
const result = store.authenticate(assertionFromBrowser);
if (result.verified) {
  // A sessão HTTP segura, autorização e cookies são responsabilidade do app.
}
```

O exemplo acima é **um esqueleto de integração, não um servidor executável**: os placeholders pressupõem um credenciamento legítimo. Para demonstração completa, use `npm run demo`.

## Políticas e limitações relevantes

- **Origem canônica HTTPS igual ao RP ID:** o perfil v0.1.0 exige `https://login.example.org` com RP ID `login.example.org`. Não suporta aplicações com RP ID em domínio pai, `localhost` ou origens alternativas.
- **Sem extensions WebAuthn**: o perfil aceita `authenticatorData` com 37 bytes, sem ED ou attested data; rejeita extras como medida conservadora. Alguns autenticadores e plataformas precisarão de implementação adicional.
- **Sign counter**: passkeys sincronizadas frequentemente usam `signCount = 0`. O projeto admite esses casos e retorna `counterSupported=false`; contador zero **não prova proteção contra clonagem**.
- **Backup flags**: faz correspondência da elegibilidade de backup com o cadastro da credencial; `backupState` pode mudar após a autenticação e é atualizado em memória.
- **Replay/atomicidade**: o `CeremonyStore` utiliza estado local síncrono. Isso fornece consumo de challenge apenas dentro de **uma instância Node.js**. Para ambientes distribuídos, implemente uma transação em Redis/PostgreSQL que consuma challenges e atualize contadores **atomicamente**.
- **Registro e autenticação**: a validade da chave registrada depende de um fluxo de cadastro que esta biblioteca não implementa; a demo não substitui cerimônia real de registro.
- **Sem identidade de usuário nem sessão HTTP**: autenticador confirma posse da chave vinculada à credencial, não autorização individual, autenticação federada ou transporte HTTP seguro.
- **Comparação de flags/UV** não garante que a plataforma inteira esteja íntegra ou que uma chave foi provisionada com a política de segurança desejada.

Consulte [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) e **[Guia de armazenamento distribuído e transações](docs/DISTRIBUTED_STORE.md)**.

## Testes e CI

```bash
npm run check
npm test
npm run demo
npm audit --audit-level=high
```

GitHub Actions executará a matriz **Ubuntu/Windows/macOS × Node 22/24**, testes, verificação sintática, empacotamento e auditoria npm após o código ser publicado. **Não atribua aprovação aos jobs remotos antes da execução real no GitHub.**

## Referências

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [Google — Server-side passkey authentication](https://developers.google.com/identity/passkeys/developer-guides/server-authentication)
- [OWASP Passkey Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Passkey_Security_Cheat_Sheet.html)
- [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn)

**MIT License — © 2026 Felipe Watter.**