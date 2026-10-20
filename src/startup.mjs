// Only trusted, fixed messages may reach startup logs. Never print cause/message/detail from pg or URL errors.
export class StartupError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const failures = {
  '28P01': ['DATABASE_AUTH_FAILED', 'Autenticação recusada pelo banco. Confira usuário, senha e codificação dos caracteres na URL.'],
  '28000': ['DATABASE_AUTH_FAILED', 'Autenticação recusada pelo banco. Confira usuário e senha da conexão.'],
  '3D000': ['DATABASE_NOT_FOUND', 'Nome do banco inválido. Use a mesma database da API.'],
  '42501': ['DATABASE_PERMISSION_DENIED', 'Permissões insuficientes. Confira os papéis e reaplique db/001_admin.sql como proprietário.'],
  '42P01': ['ADMIN_OBJECTS_MISSING', 'Objetos do Admin ausentes. Execute db/001_admin.sql na mesma base das URLs do Admin.'],
  '3F000': ['ADMIN_OBJECTS_MISSING', 'Schema do Admin ausente. Execute db/001_admin.sql na mesma base das URLs do Admin.'],
  ENOTFOUND: ['DATABASE_DNS_FAILED', 'Endereço do banco não encontrado. Confira o host da conexão.'],
  EAI_AGAIN: ['DATABASE_DNS_FAILED', 'Falha temporária de DNS ao localizar o banco.'],
  ECONNREFUSED: ['DATABASE_UNREACHABLE', 'Conexão recusada pelo banco. Confira o host, porta e disponibilidade.'],
  ETIMEDOUT: ['DATABASE_TIMEOUT', 'Tempo de conexão esgotado. Confira a disponibilidade do banco e tente novamente.'],
  ECONNRESET: ['DATABASE_UNREACHABLE', 'A conexão com o banco foi interrompida.'],
  CERT_HAS_EXPIRED: ['DATABASE_TLS_FAILED', 'Certificado TLS expirado. Não desative a verificação do certificado.'],
  DEPTH_ZERO_SELF_SIGNED_CERT: ['DATABASE_TLS_FAILED', 'Certificado TLS não confiável. Confira a conexão do provedor.'],
  SELF_SIGNED_CERT_IN_CHAIN: ['DATABASE_TLS_FAILED', 'Cadeia TLS não confiável. Confira a conexão do provedor.'],
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: ['DATABASE_TLS_FAILED', 'Certificado TLS não pôde ser verificado. Confira a conexão do provedor.'],
  ERR_TLS_CERT_ALTNAME_INVALID: ['DATABASE_TLS_FAILED', 'O certificado TLS não corresponde ao host informado. Confira o host.']
};
const stages = new Set(['CONFIG', 'DATABASE', 'READER', 'LOGGER', 'VIEWS', 'SERVER']);
export function startupDiagnostic(error, stage = 'SERVER') {
  const mapped = error instanceof StartupError ? [error.code, error.message] : failures[error?.code];
  const [code, message] = mapped || ['STARTUP_FAILED', 'Falha não identificada na inicialização. Confira as variáveis e permissões conforme README.'];
  return { event: 'startup.failed', stage: stages.has(stage) ? stage : 'SERVER', code, message };
}
export async function startupStep(stage, action) {
  try { return await action(); }
  catch (error) {
    const diagnostic = startupDiagnostic(error, stage);
    const safe = new StartupError(diagnostic.code, diagnostic.message);
    safe.stage = diagnostic.stage;
    throw safe;
  }
}
