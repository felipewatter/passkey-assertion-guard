# Contribuindo com Passkey Assertion Guard

Requer Node.js 22 ou 24. Teste local:

```bash
npm ci --ignore-scripts
npm run check
npm test
npm run demo
npm audit --audit-level=high
```

Mantenha alterações pequenas e com testes adversariais para toda mudança de semântica criptográfica. Não inclua credenciais, assertions, cookies, logs de autenticação ou chaves privadas reais em commits ou issues.

Consulte `SECURITY.md` antes de propor relaxamento de origem, algoritmos, validação de flags, uso único de challenge ou regras de contador. Sem auditoria independente, qualquer ampliação do escopo deve ser claramente documentada.
