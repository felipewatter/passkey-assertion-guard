# Política de segurança — Passkey Assertion Guard

## Comunicação de vulnerabilidades

Prefira GitHub Security Advisories / Private Vulnerability Reporting (quando disponível). Não publique chaves privadas de autenticadores, challenges reais, assertions associadas a usuários ou credenciais de clientes em issues.

## Modelo e fronteiras de confiança

- A **chave pública confiável** tem de vir de um servidor que realizou registro WebAuthn legítimo e com validação completa. A biblioteca de verificação de autenticação **não implementa esse cadastro**.
- O `challenge` precisa ser emitido e mantido pelo servidor, ser vinculado a tentativa de login e à credencial correta, expirar e ser consumido **uma única vez**; a demo implementa isso somente em memória.
- Origem e RP ID são fixados pelo backend; **não** devem ser lidos do JSON da assertion como expectativa.
- A assinatura é verificada usando dados binários brutos: `authenticatorData || SHA256(clientDataJSON)`, ES256 ou Ed25519. Algoritmos desconhecidos, chaves extras e parâmetros inesperados são rejeitados.
- UP/UV, BE/BS e contadores são verificados, mas seus significados dependem das garantias do autenticador e da validação prévia no registro.

## Recomendações para ambientes de produção

**Use bibliotecas FIDO2/WebAuthn especializadas, mantidas e auditadas, como SimpleWebAuthn, para aplicações reais.** Este projeto é um demonstrador defensivo de verificação, não uma implementação exaustiva da especificação.

Para ambientes distribuídos, utilize armazenamento transacional (PostgreSQL/Redis com operações atômicas apropriadas) para estados de challenge, índices de credencial, contador, limite de tentativas e revogação. Teste condições de concorrência e garanta que uma mesma resposta não gere duas sessões.

Implemente HTTPS, cookies HttpOnly/Secure/SameSite conforme o desenho de aplicação, proteção CSRF quando cabível, limites de frequência por IP/conta, registro de eventos sem dados sensíveis, e opções de recuperação de conta seguras.

## Riscos residuais documentados

1. **Sem registro:** não comprova que a credencial foi criada em um dispositivo autorizado.
2. **Sem proteção multi-instância:** o `CeremonyStore` em memória não impede replay entre processos/reinícios.
3. **Sem validação de attestation:** não comprova fabricante, modelo, hardware, segurança de plataforma ou nível FIDO.
4. **Sem extensões WebAuthn:** estruturas com extensions são rejeitadas, mesmo que válidas pela especificação.
5. **Política restrita de domínio:** exige RP ID idêntico ao hostname HTTPS exato; casos de RP ID pai/múltiplas origens e localhost não têm suporte.
6. **Contadores zero:** podem ser legítimos (especialmente credenciais sincronizadas), mas não oferecem detecção de clonagem por contador.
7. **Credenciais sincronizadas:** flags BE/BS apenas refletem bits assinados; não atestam dispositivo único.
8. **DoS em camada de transporte:** tamanho de request HTTP, autenticação, limites de CPU por origem e armazenamento persistente são obrigações do backend.
9. **Chaves de teste:** `demoAuthenticator` gera material privado apenas dentro do processo e existe para testes; nunca o use como fluxo de registro real.
10. **Sem testes independentes:** a aprovação automatizada não é certificação de segurança.

## Saídas e privacidade

A API retorna sinalizadores mínimos e contador atualizado; não retorna challenge, assinatura, chave pública ou dados do cliente. A CLI de demonstração não imprime material criptográfico. Erros genéricos evitam expor dados de autenticação.