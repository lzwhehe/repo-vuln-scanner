// Supplemental pure matching rules inspired by Coff0xc/Github-API-scan.
// Source: https://github.com/Coff0xc/Github-API-scan (MIT License).
// These rules only identify leaked-looking tokens; they do not verify or use credentials.

const SOURCE_RULE_SET = "coff0xc-github-api-scan";

const defaultAdvice = "Treat this credential-like value as exposed. Rotate it if it belongs to you and audit recent usage.";

function r({
  id,
  label,
  provider,
  category,
  pattern,
  severity = "critical",
  evidenceLevel = "confirmed_pattern",
  contextPattern,
  secretGroup,
  actionable = true,
  advice = defaultAdvice
}) {
  return {
    id,
    label,
    provider,
    category,
    severity,
    evidenceLevel,
    contextPattern,
    secretGroup,
    actionable,
    sourceRuleSet: SOURCE_RULE_SET,
    pattern,
    advice
  };
}

function contextual(config) {
  return r({
    ...config,
    evidenceLevel: config.evidenceLevel || "contextual_pattern",
    contextPattern: config.contextPattern || new RegExp(config.provider.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i")
  });
}

export const coff0xcSupplementalRules = [
  r({ id: "coff0xc-slack-token", label: "Slack token", provider: "slack", category: "messaging", pattern: /\bxox[baprs]-(?:[0-9]{10,13}-){2,3}[A-Za-z0-9]{24,}\b/g }),
  r({ id: "coff0xc-slack-webhook", label: "Slack webhook", provider: "slack", category: "messaging", severity: "high", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g }),
  r({ id: "coff0xc-discord-token", label: "Discord bot token", provider: "discord", category: "messaging", pattern: /\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/g }),
  r({ id: "coff0xc-discord-webhook", label: "Discord webhook", provider: "discord", category: "messaging", severity: "high", pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,}/g }),
  r({ id: "coff0xc-telegram-bot", label: "Telegram bot token", provider: "telegram", category: "messaging", pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g }),
  r({ id: "coff0xc-twilio-sid", label: "Twilio account SID", provider: "twilio", category: "messaging", severity: "high", pattern: /\bAC[a-f0-9]{32}\b/g }),
  contextual({ id: "coff0xc-twilio-auth", label: "Twilio auth token", provider: "twilio", category: "messaging", pattern: /\b[a-f0-9]{32}\b/gi }),
  r({ id: "coff0xc-sendgrid", label: "SendGrid API key", provider: "sendgrid", category: "messaging", pattern: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}\b/g }),
  r({ id: "coff0xc-mailgun", label: "Mailgun API key", provider: "mailgun", category: "messaging", pattern: /\bkey-[A-Za-z0-9]{32}\b/g }),
  r({ id: "coff0xc-mailchimp", label: "Mailchimp API key", provider: "mailchimp", category: "messaging", severity: "high", pattern: /\b[a-f0-9]{32}-us\d{1,2}\b/g }),
  r({ id: "coff0xc-postmark", label: "Postmark server token", provider: "postmark", category: "messaging", severity: "high", pattern: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi, contextPattern: /postmark/i, evidenceLevel: "contextual_pattern" }),

  r({ id: "coff0xc-digitalocean", label: "DigitalOcean token", provider: "digitalocean", category: "cloud", pattern: /\bdop_v1_[a-f0-9]{64}\b/g }),
  contextual({ id: "coff0xc-digitalocean-oauth", label: "DigitalOcean OAuth token", provider: "digitalocean", category: "cloud", pattern: /\b[a-f0-9]{64}\b/gi }),
  contextual({ id: "coff0xc-heroku", label: "Heroku API key", provider: "heroku", category: "cloud", pattern: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi }),
  contextual({ id: "coff0xc-cloudflare-token", label: "Cloudflare API token", provider: "cloudflare", category: "cloud", pattern: /\b[A-Za-z0-9_-]{40}\b/g }),
  contextual({ id: "coff0xc-cloudflare-global", label: "Cloudflare global API key", provider: "cloudflare", category: "cloud", pattern: /\b[a-f0-9]{37}\b/gi }),
  contextual({ id: "coff0xc-vercel", label: "Vercel token", provider: "vercel", category: "cloud", pattern: /\b[A-Za-z0-9]{24}\b/g }),
  contextual({ id: "coff0xc-linode", label: "Linode token", provider: "linode", category: "cloud", pattern: /\b[a-f0-9]{64}\b/gi }),
  contextual({ id: "coff0xc-vultr", label: "Vultr API key", provider: "vultr", category: "cloud", pattern: /\b[A-Z0-9]{36}\b/g }),

  r({ id: "coff0xc-gitlab-pat", label: "GitLab personal access token", provider: "gitlab", category: "devops", pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g }),
  r({ id: "coff0xc-gitlab-pipeline", label: "GitLab pipeline trigger token", provider: "gitlab", category: "devops", severity: "high", pattern: /\bglpt-[A-Za-z0-9]{20,}\b/g }),
  r({ id: "coff0xc-gitlab-runner", label: "GitLab runner token", provider: "gitlab", category: "devops", severity: "high", pattern: /\bGR1348941[A-Za-z0-9_-]{20}\b/g }),
  contextual({ id: "coff0xc-bitbucket", label: "Bitbucket token", provider: "bitbucket", category: "devops", pattern: /\b[A-Za-z0-9]{20,}\b/g }),
  r({ id: "coff0xc-circleci", label: "CircleCI token", provider: "circleci", category: "devops", pattern: /\bcircle(?:ci)?[_-]?(?:token|api)[^A-Za-z0-9]*([a-f0-9]{40})\b/gi, secretGroup: 1 }),
  r({ id: "coff0xc-travis-ci", label: "Travis CI token", provider: "travis-ci", category: "devops", severity: "high", pattern: /\btravis[_-]?(?:ci)?[_-]?(?:token|api)[^A-Za-z0-9]*([A-Za-z0-9]{22})\b/gi, secretGroup: 1 }),
  r({ id: "coff0xc-npm-token", label: "npm access token", provider: "npm", category: "devops", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g }),
  r({ id: "coff0xc-npm-auth", label: "npm registry auth token", provider: "npm", category: "devops", pattern: /\/\/registry\.npmjs\.org\/:_authToken=([A-Za-z0-9_-]+)/g, secretGroup: 1 }),
  r({ id: "coff0xc-pypi", label: "PyPI API token", provider: "pypi", category: "devops", pattern: /\bpypi-[A-Za-z0-9_-]{100,}\b/g }),
  r({ id: "coff0xc-rubygems", label: "RubyGems API key", provider: "rubygems", category: "devops", pattern: /\brubygems_[a-f0-9]{48}\b/gi }),
  r({ id: "coff0xc-nuget", label: "NuGet API key", provider: "nuget", category: "devops", severity: "high", pattern: /\boy2[a-z0-9]{43}\b/g }),
  r({ id: "coff0xc-docker-hub", label: "Docker Hub access token", provider: "dockerhub", category: "devops", severity: "high", pattern: /\bdckr_pat_[A-Za-z0-9_-]{27,}\b/g }),

  contextual({ id: "coff0xc-datadog-api", label: "Datadog API key", provider: "datadog", category: "monitoring", pattern: /\b[a-f0-9]{32}\b/gi }),
  contextual({ id: "coff0xc-datadog-app", label: "Datadog application key", provider: "datadog", category: "monitoring", severity: "high", pattern: /\b[a-f0-9]{40}\b/gi }),
  r({ id: "coff0xc-sentry", label: "Sentry auth token", provider: "sentry", category: "monitoring", severity: "high", pattern: /\bsntrys_[A-Za-z0-9]{58,}\b/g }),
  r({ id: "coff0xc-sentry-dsn", label: "Sentry DSN", provider: "sentry", category: "monitoring", severity: "low", actionable: false, pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/\d+/g }),
  r({ id: "coff0xc-newrelic-api", label: "New Relic API key", provider: "newrelic", category: "monitoring", pattern: /\bNRAK-[A-Z0-9]{27}\b/g }),
  r({ id: "coff0xc-newrelic-license", label: "New Relic license key", provider: "newrelic", category: "monitoring", severity: "high", pattern: /\b[a-f0-9]{40}NRAL\b/gi }),
  r({ id: "coff0xc-newrelic-browser", label: "New Relic browser key", provider: "newrelic", category: "monitoring", severity: "low", actionable: false, pattern: /\bNRJS-[a-f0-9]{19}\b/gi }),
  contextual({ id: "coff0xc-pagerduty", label: "PagerDuty token", provider: "pagerduty", category: "monitoring", severity: "high", pattern: /\b[A-Za-z0-9+]{20}\b/g }),
  contextual({ id: "coff0xc-pagerduty-integration", label: "PagerDuty integration key", provider: "pagerduty", category: "monitoring", severity: "high", pattern: /\b[a-f0-9]{32}\b/gi }),
  contextual({ id: "coff0xc-elastic-apm", label: "Elastic APM token", provider: "elastic", category: "monitoring", severity: "high", pattern: /\b[A-Za-z0-9]{32,}\b/g }),
  contextual({ id: "coff0xc-splunk-hec", label: "Splunk HEC token", provider: "splunk", category: "monitoring", severity: "high", pattern: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi }),

  r({ id: "coff0xc-notion", label: "Notion integration token", provider: "notion", category: "collaboration", pattern: /\bsecret_[A-Za-z0-9]{43}\b/g }),
  r({ id: "coff0xc-linear", label: "Linear API key", provider: "linear", category: "collaboration", severity: "high", pattern: /\blin_api_[A-Za-z0-9]{40}\b/g }),
  r({ id: "coff0xc-asana", label: "Asana personal access token", provider: "asana", category: "collaboration", severity: "high", pattern: /\b1\/\d{16,}:[a-f0-9]{32}\b/gi }),
  r({ id: "coff0xc-airtable", label: "Airtable legacy API key", provider: "airtable", category: "collaboration", severity: "high", pattern: /\bkey[A-Za-z0-9]{14}\b/g }),
  r({ id: "coff0xc-airtable-pat", label: "Airtable personal access token", provider: "airtable", category: "collaboration", pattern: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g }),
  contextual({ id: "coff0xc-atlassian", label: "Atlassian token", provider: "atlassian", category: "collaboration", severity: "high", pattern: /\b[A-Za-z0-9]{24}\b/g, contextPattern: /(atlassian|jira|confluence)/i }),
  contextual({ id: "coff0xc-trello", label: "Trello token", provider: "trello", category: "collaboration", severity: "high", pattern: /\b[a-f0-9]{32}\b/gi }),
  r({ id: "coff0xc-monday", label: "monday.com JWT token", provider: "monday", category: "collaboration", severity: "high", pattern: /\beyJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g }),
  r({ id: "coff0xc-clickup", label: "ClickUp API token", provider: "clickup", category: "collaboration", severity: "high", pattern: /\bpk_\d+_[A-Z0-9]{32}\b/g }),

  contextual({ id: "coff0xc-segment", label: "Segment key", provider: "segment", category: "analytics", severity: "high", pattern: /\b[A-Za-z0-9]{32}\b/g }),
  contextual({ id: "coff0xc-mixpanel", label: "Mixpanel key", provider: "mixpanel", category: "analytics", severity: "medium", pattern: /\b[a-f0-9]{32}\b/gi }),
  contextual({ id: "coff0xc-amplitude", label: "Amplitude key", provider: "amplitude", category: "analytics", severity: "medium", pattern: /\b[a-f0-9]{32}\b/gi }),
  contextual({ id: "coff0xc-algolia-api", label: "Algolia API key", provider: "algolia", category: "analytics", severity: "high", pattern: /\b[a-f0-9]{32}\b/gi }),
  contextual({ id: "coff0xc-algolia-admin", label: "Algolia admin API key", provider: "algolia", category: "analytics", pattern: /\b[a-f0-9]{32}\b/gi, contextPattern: /algolia.*admin|admin.*algolia/i }),
  r({ id: "coff0xc-ga-measurement", label: "Google Analytics measurement ID", provider: "google-analytics", category: "analytics", severity: "low", actionable: false, pattern: /\bG-[A-Z0-9]{10}\b/g }),
  r({ id: "coff0xc-ga-tracking", label: "Google Analytics tracking ID", provider: "google-analytics", category: "analytics", severity: "low", actionable: false, pattern: /\bUA-\d{4,10}-\d{1,4}\b/g }),
  r({ id: "coff0xc-fullstory", label: "FullStory org ID", provider: "fullstory", category: "analytics", severity: "low", actionable: false, pattern: /\bo-[A-Z0-9]+-na1\b/g }),
  contextual({ id: "coff0xc-hotjar", label: "Hotjar site ID", provider: "hotjar", category: "analytics", severity: "low", actionable: false, pattern: /\b\d{7}\b/g }),

  contextual({ id: "coff0xc-zendesk", label: "Zendesk token", provider: "zendesk", category: "customer-data", severity: "high", pattern: /\b[A-Za-z0-9]{40}\b/g }),
  r({ id: "coff0xc-intercom", label: "Intercom token", provider: "intercom", category: "customer-data", severity: "high", pattern: /\bdG9rO[A-Za-z0-9_-]{50,}\b/g }),
  contextual({ id: "coff0xc-freshdesk", label: "Freshdesk token", provider: "freshdesk", category: "customer-data", severity: "high", pattern: /\b[A-Za-z0-9]{20}\b/g }),
  contextual({ id: "coff0xc-hubspot", label: "HubSpot token", provider: "hubspot", category: "customer-data", severity: "high", pattern: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi }),
  r({ id: "coff0xc-hubspot-pat", label: "HubSpot private app token", provider: "hubspot", category: "customer-data", severity: "high", pattern: /\bpat-na1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi }),
  contextual({ id: "coff0xc-salesforce", label: "Salesforce token", provider: "salesforce", category: "customer-data", severity: "high", pattern: /\b[A-Za-z0-9]{24}\b/g }),

  r({ id: "coff0xc-mapbox", label: "Mapbox public token", provider: "mapbox", category: "maps", severity: "low", actionable: false, pattern: /\bpk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{22}\b/g }),
  r({ id: "coff0xc-mapbox-secret", label: "Mapbox secret token", provider: "mapbox", category: "maps", severity: "high", pattern: /\bsk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{22}\b/g }),
  r({ id: "coff0xc-google-maps", label: "Google Maps API key", provider: "google", category: "maps", severity: "high", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g }),
  contextual({ id: "coff0xc-here", label: "HERE API key", provider: "here", category: "maps", severity: "high", pattern: /\b[A-Za-z0-9_-]{43}\b/g, contextPattern: /here\.com|here[_-]?api|here[_-]?key/i }),
  contextual({ id: "coff0xc-tomtom", label: "TomTom API key", provider: "tomtom", category: "maps", severity: "high", pattern: /\b[A-Za-z0-9]{32}\b/g }),

  r({ id: "coff0xc-stripe-secret", label: "Stripe live secret key", provider: "stripe", category: "payment", pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/g }),
  r({ id: "coff0xc-stripe-publishable", label: "Stripe live publishable key", provider: "stripe", category: "payment", severity: "low", actionable: false, pattern: /\bpk_live_[A-Za-z0-9]{24,}\b/g }),
  r({ id: "coff0xc-stripe-restricted", label: "Stripe restricted key", provider: "stripe", category: "payment", severity: "high", pattern: /\brk_live_[A-Za-z0-9]{24,}\b/g }),
  r({ id: "coff0xc-stripe-test", label: "Stripe test key", provider: "stripe", category: "payment", severity: "medium", pattern: /\b[sr]k_test_[A-Za-z0-9]{24,}\b/g }),
  contextual({ id: "coff0xc-paypal-client", label: "PayPal client token", provider: "paypal", category: "payment", severity: "high", pattern: /\bA[A-Za-z0-9_-]{79}\b/g }),
  r({ id: "coff0xc-square", label: "Square access token", provider: "square", category: "payment", severity: "high", pattern: /\bsq0atp-[A-Za-z0-9_-]{22}\b/g }),
  r({ id: "coff0xc-square-app", label: "Square application ID", provider: "square", category: "payment", severity: "low", actionable: false, pattern: /\bsq0idp-[A-Za-z0-9_-]{22}\b/g }),
  r({ id: "coff0xc-braintree", label: "Braintree access token", provider: "braintree", category: "payment", pattern: /\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b/g }),
  r({ id: "coff0xc-adyen", label: "Adyen API key", provider: "adyen", category: "payment", severity: "high", pattern: /\bAQE[A-Za-z0-9]{10,}\b/g, contextPattern: /adyen/i, evidenceLevel: "contextual_pattern" }),

  contextual({ id: "coff0xc-twitter-api", label: "Twitter/X API key", provider: "twitter", category: "social", severity: "high", pattern: /\b[A-Za-z0-9]{25}\b/g }),
  r({ id: "coff0xc-twitter-bearer", label: "Twitter/X bearer token", provider: "twitter", category: "social", severity: "high", pattern: /\bAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+\b/g }),
  r({ id: "coff0xc-facebook", label: "Facebook access token", provider: "facebook", category: "social", severity: "high", pattern: /\bEAA[A-Za-z0-9]{100,}\b/g }),
  r({ id: "coff0xc-instagram", label: "Instagram token", provider: "instagram", category: "social", severity: "high", pattern: /\bIGQV[A-Za-z0-9_-]{100,}\b/g }),
  contextual({ id: "coff0xc-linkedin", label: "LinkedIn token", provider: "linkedin", category: "social", severity: "high", pattern: /\b[a-z0-9]{14}\b/g }),
  r({ id: "coff0xc-youtube", label: "YouTube/Google API key", provider: "youtube", category: "social", severity: "high", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g }),

  r({ id: "coff0xc-aws-access", label: "AWS access key id", provider: "aws", category: "cloud", severity: "high", pattern: /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g }),
  contextual({ id: "coff0xc-aws-secret", label: "AWS secret access key", provider: "aws", category: "cloud", pattern: /\b[A-Za-z0-9/+=]{40}\b/g, contextPattern: /(aws|secret|key|access[_-]?key)/i }),
  r({ id: "coff0xc-aws-session", label: "AWS session token", provider: "aws", category: "cloud", severity: "high", pattern: /\bFwoGZXIvYXdzE[A-Za-z0-9/+=]+\b/g }),
  r({ id: "coff0xc-gcp-service-account", label: "GCP service account JSON", provider: "gcp", category: "cloud", pattern: /"type"\s*:\s*"service_account"/g }),
  r({ id: "coff0xc-azure-storage", label: "Azure storage key", provider: "azure", category: "cloud", pattern: /\b[A-Za-z0-9+/]{86}==\b/g, contextPattern: /(azure|account[_-]?key|storage)/i, evidenceLevel: "contextual_pattern" }),
  r({ id: "coff0xc-azure-sas", label: "Azure SAS token", provider: "azure", category: "cloud", severity: "high", pattern: /\bsv=\d{4}-\d{2}-\d{2}&s[a-z]=.*&sig=[A-Za-z0-9%/+=]+/g }),

  r({ id: "coff0xc-firebase-db", label: "Firebase database URL", provider: "firebase", category: "database", severity: "low", actionable: false, pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g }),
  r({ id: "coff0xc-supabase", label: "Supabase JWT key", provider: "supabase", category: "database", severity: "high", pattern: /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, contextPattern: /supabase/i, evidenceLevel: "contextual_pattern" }),
  r({ id: "coff0xc-planetscale", label: "PlanetScale connection URL", provider: "planetscale", category: "database", pattern: /\bmysql:\/\/[a-z0-9]+:[A-Za-z0-9]+@[a-z0-9.-]+\.psdb\.cloud\/[A-Za-z0-9_-]+\b/g }),
  r({ id: "coff0xc-mongodb", label: "MongoDB connection URL", provider: "mongodb", category: "database", severity: "high", pattern: /\bmongodb(?:\+srv)?:\/\/[A-Za-z0-9:._@%/-]+/g }),
  r({ id: "coff0xc-redis", label: "Redis connection URL", provider: "redis", category: "database", severity: "high", pattern: /\bredis:\/\/[A-Za-z0-9:._@%/-]+/g }),

  r({ id: "coff0xc-shopify-access", label: "Shopify access token", provider: "shopify", category: "commerce", severity: "high", pattern: /\bshpat_[a-f0-9]{32}\b/gi }),
  r({ id: "coff0xc-shopify-secret", label: "Shopify shared secret", provider: "shopify", category: "commerce", severity: "high", pattern: /\bshpss_[a-f0-9]{32}\b/gi }),
  contextual({ id: "coff0xc-okta", label: "Okta token", provider: "okta", category: "identity", severity: "high", pattern: /\b00[A-Za-z0-9_-]{40}\b/g }),
  contextual({ id: "coff0xc-auth0", label: "Auth0 token", provider: "auth0", category: "identity", severity: "high", pattern: /\b[A-Za-z0-9]{32,}\b/g }),

  r({ id: "coff0xc-jwt", label: "JWT", provider: "jwt", category: "auth", severity: "medium", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g }),
  r({ id: "coff0xc-private-key-pem", label: "Private key block", provider: "private-key", category: "private-key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g }),
  r({ id: "coff0xc-ssh-private-key", label: "OpenSSH private key", provider: "private-key", category: "private-key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g }),
  r({ id: "coff0xc-pgp-private-key", label: "PGP private key", provider: "private-key", category: "private-key", pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g }),
  r({ id: "coff0xc-generic-api-key", label: "Generic API key assignment", provider: "generic", category: "generic", severity: "medium", evidenceLevel: "generic_entropy", pattern: /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/gi, secretGroup: 1 }),

  r({ id: "coff0xc-gemini", label: "Google Gemini API key", provider: "gemini", category: "ai", severity: "high", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g }),
  r({ id: "coff0xc-cohere", label: "Cohere API key", provider: "cohere", category: "ai", pattern: /\b[A-Za-z0-9_-]{40}\b/g, contextPattern: /cohere/i, evidenceLevel: "contextual_pattern" }),
  r({ id: "coff0xc-mistral", label: "Mistral API key", provider: "mistral", category: "ai", pattern: /\b[A-Za-z0-9]{32}\b/g, contextPattern: /mistral/i, evidenceLevel: "contextual_pattern" }),
  r({ id: "coff0xc-together", label: "Together AI API key", provider: "together", category: "ai", pattern: /\b[A-Za-z0-9_-]{40,}\b/g, contextPattern: /together/i, evidenceLevel: "contextual_pattern" }),
  r({ id: "coff0xc-fireworks", label: "Fireworks AI API key", provider: "fireworks", category: "ai", pattern: /\bfw_[A-Za-z0-9_-]{20,}\b/g }),
  r({ id: "coff0xc-anyscale", label: "Anyscale API key", provider: "anyscale", category: "ai", pattern: /\besecret_[A-Za-z0-9_-]{20,}\b/g })
];
