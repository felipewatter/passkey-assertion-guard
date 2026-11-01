# Passkey Assertion Guard v0.1.0 — WebAuthn Authentication Assertion Verification

Versão inicial de um verificador defensivo de assertions WebAuthn, com assinatura ES256 e Ed25519, comparação de origin/RP/challenge, validação UP/UV e estado de cerimônia em memória com consumo único de desafio.

Acompanham testes adversariais, GitHub Actions em matriz Node 22/24 (Ubuntu, Windows, macOS), documentação de segurança, modelo de ameaças, arquitetura e licença MIT.

**Limites:** projeto experimental, não implementa registro/attestation, backend de produção, autenticação distribuída, sessão HTTP nem certificação FIDO2. Use biblioteca amplamente testada e com auditoria externa em sistemas reais.
