/** Redact command-line secrets before audit, UI, terminal mirroring or evidence persistence. */
const SECRET_ENV = '(?:TOKEN|PASSWORD|PASS|SECRET|API_KEY|APIKEY|ACCESS_TOKEN|AUTH_TOKEN)'
const SECRET_OPT = '(?:password|passwd|pass|token|secret|api-key|apikey|access-token|auth-token)'

export function redactCommandSecrets(command: string): string {
  let value = command

  // Environment assignments, including `env PASSWORD=x command`.
  value = value.replace(new RegExp(`\\b(${SECRET_ENV})=(?:"[^"]*"|'[^']*'|[^\\s]+)`, 'gi'), '$1=******')

  // Common long options: --password x / --token=x / --api-key x.
  value = value.replace(new RegExp(`(\\s--${SECRET_OPT})(?:=|\\s+)("[^"]*"|'[^']*'|\\S+)`, 'gi'), '$1=******')

  // Redis password options (separate or equals form).
  value = value.replace(/(\bredis-cli\b[^|;]*?\s(?:-a|--pass))(?:=|\s+)("[^"]*"|'[^']*'|\S+)/gi, '$1 ******')

  // mysql/mariadb -psecret, -p secret, --password=secret and --password secret.
  value = value.replace(/(\b(?:mysql|mariadb)\b[^|;]*?\s-p)(?!\s(?:-|$))("[^"]*"|'[^']*'|\S+)/gi, '$1******')
  value = value.replace(/(\b(?:mysql|mariadb)\b[^|;]*?\s(?:-p|--password))(?:=|\s+)("[^"]*"|'[^']*'|\S+)/gi, '$1=******')

  // sshpass and docker login password forms.
  value = value.replace(/(\bsshpass\b[^|;]*?\s-p)(?:\s+)?("[^"]*"|'[^']*'|\S+)/gi, '$1 ******')
  value = value.replace(/(\bdocker\s+login\b[^|;]*?\s(?:-p|--password))(?:=|\s+)("[^"]*"|'[^']*'|\S+)/gi, '$1=******')

  // curl basic auth: preserve the username for audit value.
  value = value.replace(/(\bcurl\b[^|;]*?\s(?:-u|--user))(?:=|\s+)("?)([^\s"':]+):([^\s"']+)\2/gi, '$1 $2$3:******$2')

  // Authorization/API-key/Cookie headers in arbitrary command arguments/log echoes.
  value = value.replace(/(Authorization\s*:\s*Bearer\s+)[^\s"']+/gi, '$1******')
  value = value.replace(/(Authorization\s*:\s*Basic\s+)[^\s"']+/gi, '$1******')
  value = value.replace(/((?:X-API-Key|Api-Key)\s*:\s*)[^\s"']+/gi, '$1******')
  value = value.replace(/(Cookie\s*:\s*)[^\r\n"']+/gi, '$1******')

  // Credentials embedded in common URI forms: scheme://user:pass@host.
  value = value.replace(/([a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:)[^\s@/]+(@)/gi, '$1******$2')

  // JVM/system-property style secrets: -Ddb.password=x, -Dtoken=x.
  value = value.replace(/(-D[A-Za-z0-9_.-]*(?:password|passwd|token|secret|api[_-]?key)[A-Za-z0-9_.-]*=)("[^"]*"|'[^']*'|\S+)/gi, '$1******')

  return value
}

export function normalizedRedactedCommand(command: string): string {
  return redactCommandSecrets(command).trim().replace(/\s+/g, ' ')
}
