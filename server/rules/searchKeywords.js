// GitHub repository search query fragments inspired by Coff0xc/Github-API-scan.
// Source: https://github.com/Coff0xc/Github-API-scan (MIT License).

export const coff0xcSearchQueries = [
  "SLACK_TOKEN OR SLACK_WEBHOOK in:file",
  "xoxb- OR hooks.slack.com/services in:file",
  "DISCORD_TOKEN OR discord.com/api/webhooks in:file",
  "TELEGRAM_BOT_TOKEN OR bot_token in:file",
  "TWILIO_AUTH_TOKEN OR SENDGRID_API_KEY in:file",
  "MAILGUN_API_KEY OR MAILCHIMP_API_KEY in:file",
  "DIGITALOCEAN_TOKEN OR dop_v1_ in:file",
  "HEROKU_API_KEY OR CLOUDFLARE_API_TOKEN in:file",
  "VERCEL_TOKEN OR LINODE_TOKEN OR VULTR_API_KEY in:file",
  "GITLAB_TOKEN OR glpat- OR CIRCLECI_TOKEN in:file",
  "_authToken OR npm_ OR pypi- in:file",
  "DOCKERHUB_TOKEN OR dckr_pat_ in:file",
  "DATADOG_API_KEY OR SENTRY_AUTH_TOKEN OR sntrys_ in:file",
  "NEW_RELIC_LICENSE_KEY OR PAGERDUTY_API_KEY in:file",
  "NOTION_TOKEN OR secret_ in:file",
  "LINEAR_API_KEY OR lin_api_ in:file",
  "AIRTABLE_API_KEY OR airtable in:file",
  "ALGOLIA_ADMIN_API_KEY OR MAPBOX_SECRET_TOKEN in:file",
  "STRIPE_SECRET_KEY OR sk_live_ OR rk_live_ in:file",
  "PAYPAL_CLIENT_SECRET OR BRAINTREE_ACCESS_TOKEN in:file",
  "AWS_SECRET_ACCESS_KEY OR AWS_SESSION_TOKEN in:file",
  "GOOGLE_APPLICATION_CREDENTIALS OR service_account in:file",
  "AZURE_STORAGE_KEY OR AZURE_SAS_TOKEN in:file",
  "SUPABASE_SERVICE_ROLE_KEY OR PLANETSCALE_SERVICE_TOKEN in:file",
  "mongodb+srv:// OR redis:// in:file",
  "SHOPIFY_ACCESS_TOKEN OR shpat_ in:file",
  "OKTA_TOKEN OR AUTH0_CLIENT_SECRET in:file",
  "PRIVATE KEY OR OPENSSH PRIVATE KEY in:file"
];
