# Integração distribuída: estado transacional de passkeys

Este guia descreve o **contrato de integração**, não uma implementação pronta de storage. `CeremonyStore` é uma demonstração **em memória e mono-processo**; não deve ser compartilhado entre réplicas ou usado como repositório de autenticação de produção.

## Fluxo recomendado

1. Após um registro WebAuthn autenticado e validado por uma implementação completa, persistir `credentialId`, identidade do usuário proprietário, JWK **público**, `signCount`, flags `backupEligible`/`backupState`, versão da linha e estado de revogação. Chave privada nunca entra no serviço.
2. Na solicitação de autenticação, gerar **32 bytes aleatórios criptograficamente seguros**, codificar base64url, associar no banco o **hash** do desafio à credencial e ao contexto de sessão, com expiração curta (por exemplo, 120 segundos). Vincular usuário e RP/origin definidos pelo backend; não usar dados de origem enviados pelo cliente como autoridade.
3. Receber a assertion em HTTPS e aplicar limites de payload, rate limiting e limite de tentativas. Carregar do banco o challenge esperado e a credencial previamente registrada. Invocar `verifyAssertion({assertion,credential,challenge,origin,...})`.
4. **Antes de emitir sessão**, efetuar uma única transação que verifique e consuma o desafio ainda não expirado e não consumido, confira o vínculo com a credencial, valide que a versão/contador armazenados ainda correspondem ao snapshot verificado e atualize `signCount`/`backupState`.
5. Se qualquer condição falhar, fazer **rollback**, negar sessão e iniciar **uma nova cerimônia**; não aceitar a assertion antiga nem reexecutar apenas o commit com um contador atualizado.
6. A autenticação só é concluída depois do commit. Em seguida, emitir sessão segura com políticas próprias de expiração, revogação, cookies e CSRF.

### Contrato de persistência

| Registro | Campos obrigatórios de segurança |
| --- | --- |
| Credencial | `id` único, `user_id`, chave JWK pública imutável sem material privado, `sign_count`, `backup_eligible`, `backup_state`, `version`, `revoked_at`. |
| Desafio | `hash` único, `credential_id`, `session_id`, `issued_at`, `expires_at`, `attempts`, `consumed_at`. |
| Auditoria | ID de requisição, outcome e tempo; **não registrar** challenge, assinatura, cookie ou JWK privado. |

### Exemplo conceitual de transação SQL

**Pseudocódigo de referência, não SQL pronto para aplicação:** os tipos de banco, isolamento, migrations, nomes, índices e autenticação deverão ser adaptados ao sistema hospedeiro.

```text
challenge = lookup_by_hash(challenge_hash)
credential = lookup_by_id(challenge.credential_id)
verified = verifyAssertion({
  assertion,
  credential: trusted_record,
  challenge: expected_raw_challenge,
  origin: configured_origin
})
if not verified.verified: deny

BEGIN TRANSACTION
  LOCK credential row FOR UPDATE
  LOCK challenge row FOR UPDATE
  REQUIRE challenge.session_id == current_session
  REQUIRE challenge.credential_id == credential.id
  REQUIRE challenge.expires_at > database_now()
  REQUIRE challenge.consumed_at IS NULL
  REQUIRE credential.revoked_at IS NULL
  REQUIRE credential.version == verified_snapshot.version
  REQUIRE credential.sign_count == verified_snapshot.sign_count
  # A assinatura foi verificada sobre o snapshot; nunca trocar o material público
  # da credencial entre verifyAssertion e o COMMIT.
  UPDATE challenge SET consumed_at = database_now()
  UPDATE credential SET
     sign_count = verified.signCount,
     backup_state = verified.backupState,
     version = version + 1
  COMMIT
if COMMIT not successful: deny and require a fresh challenge
issue session
```

**Observação:** contadores zero são comuns em passkeys sincronizadas. O sistema não deve afirmar resistência à clonagem quando `counterSupported=false`. A idempotência do consumo do desafio permanece obrigatória.

## Concorrência, falhas e consistência

- **Replay em réplicas:** duas requisições simultâneas com o mesmo challenge devem produzir no máximo **um** commit. Verificar em testes executados de processos distintos.
- **Contador de assinatura:** usar condição de versão/CAS ou bloqueio de linha para detectar race entre desafios diferentes. Não sobrescrever um contador mais novo com snapshot antigo.
- **Falha entre verificação e gravação:** emitir sessão somente após confirmação durável da transação. Se o resultado for desconhecido, tratar como falha, não assumir sucesso.
- **Expiração:** usar relógio do banco, limite de TTL e política para sessões interrompidas; contabilizar tentativas com atualizações atômicas para evitar brute force entre réplicas.
- **Redis:** a operação de consumo e atualização do contador deve ser implementada em um comando transacional/script Lua equivalente, com persistência adequada e sem usar combinações inseguras de `GET` + `DEL`.
- **PostgreSQL:** usar `SELECT ... FOR UPDATE`, `UPDATE ... WHERE version=? RETURNING ...` e rollback automático caso qualquer pré-condição falhe. Restrinja privilégios da conta de aplicação.
- **Segregação de usuários:** vincular credencial e challenge ao titular e à sessão; não permitir que um challenge de outro usuário autentique a conta atual.
- **Rotação/revogação:** refletir revogações imediatamente em todas as réplicas; invalidar desafios pendentes e sessões conforme a política da aplicação.

## Testes de aceitação para uso em produção

Executar em pelo menos **duas instâncias independentes** com um banco compartilhado: challenge repetido, respostas concorrentes com o mesmo challenge, challenge expirado, usuário diferente, credencial revogada entre leitura e commit, versão da credencial atualizada por outra requisição, indisponibilidade do banco, rollback e emissão de sessão após confirmação. Testar com assinatura ES256 e Ed25519 legítima, sem desativar controles WebAuthn.

O código desta biblioteca só executa a etapa **pura de verificação** e fornece a demonstração `CeremonyStore`; a implementação real dos controles transacionais e de sessão é responsabilidade da aplicação. Consulte também [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md) e [SECURITY.md](../SECURITY.md).
