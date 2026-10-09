// Trusted models and official routes, never adopted from uploaded evidence.
export const POLICY = Object.freeze({
  "model": "claude-opus-5-5",
  "host": "api.anthropic.com",
  "pcr0": "437cbab8c2e5dd11a35ae5b062fe115623a013910b7c26b333e2b3af477944d630fb1dcd76fa9a9b1eefdf1d1021dec2",
  "models": {
    "claude-fable-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-fable-5"
    },
    "claude-fable-5-1": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-fable-5-1"
    },
    "claude-haiku-4-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-haiku-4-5-20251001"
    },
    "claude-haiku-5-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-haiku-5-5"
    },
    "claude-opus-4-6": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-opus-4-6"
    },
    "claude-opus-4-7": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-opus-4-7"
    },
    "claude-opus-4-8": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-opus-4-8"
    },
    "claude-opus-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-opus-5"
    },
    "claude-opus-5-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-opus-5-5"
    },
    "claude-sonnet-4-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-sonnet-4-5-20250929"
    },
    "claude-sonnet-4-6": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-sonnet-4-6"
    },
    "claude-sonnet-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-sonnet-5"
    },
    "claude-sonnet-5-5": {
      "host": "api.anthropic.com",
      "path": "/v1/messages",
      "route": "/v1/messages",
      "signedModel": "claude-sonnet-5-5"
    },
    "deepseek-v4-flash": {
      "host": "ark.cn-beijing.volces.com",
      "path": "/api/coding/v1/messages",
      "route": "/v1/messages",
      "signedModel": "deepseek-v4-flash-ga-260731"
    },
    "deepseek-v4-pro": {
      "host": "ark.cn-beijing.volces.com",
      "path": "/api/coding/v1/messages",
      "route": "/v1/messages",
      "signedModel": "deepseek-v4-pro"
    },
    "doubao-seed-2.0-mini": {
      "host": "ark.cn-beijing.volces.com",
      "path": "/api/coding/v1/messages",
      "route": "/v1/messages",
      "signedModel": "doubao-seed-2-0-mini"
    },
    "doubao-seed-2.1-lite": {
      "host": "ark.cn-beijing.volces.com",
      "path": "/api/coding/v1/messages",
      "route": "/v1/messages",
      "signedModel": "doubao-seed-2-1-lite"
    },
    "doubao-seed-2.1-pro": {
      "host": "ark.cn-beijing.volces.com",
      "path": "/api/coding/v1/messages",
      "route": "/v1/messages",
      "signedModel": "doubao-seed-2-1-pro"
    },
    "gpt-5.5": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-5.5",
      "allowEmptyContentType": true
    },
    "gpt-5.6-luna": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-5.6-luna",
      "allowEmptyContentType": true
    },
    "gpt-5.6-sol": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-5.6-sol",
      "allowEmptyContentType": true
    },
    "gpt-5.6-terra": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-5.6-terra",
      "allowEmptyContentType": true
    },
    "gpt-6-astra": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-6-astra",
      "allowEmptyContentType": true
    },
    "gpt-6-luna": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-6-luna",
      "allowEmptyContentType": true
    },
    "gpt-6-sol": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-6-sol",
      "allowEmptyContentType": true
    },
    "gpt-6.1-sol": {
      "host": "chatgpt.com",
      "path": "/backend-api/codex/responses",
      "route": "/v1/responses",
      "signedModel": "gpt-6.1-sol",
      "allowEmptyContentType": true
    },
    "grok-4.3": {
      "host": "api.x.ai",
      "path": "/v1/responses",
      "route": "/v1/responses",
      "signedModel": "grok-4.3"
    },
    "grok-4.5": {
      "host": "api.x.ai",
      "path": "/v1/responses",
      "route": "/v1/responses",
      "signedModel": "grok-4.5"
    },
    "grok-4.6": {
      "host": "api.x.ai",
      "path": "/v1/responses",
      "route": "/v1/responses",
      "signedModel": "grok-4.6"
    },
    "grok-4.7": {
      "host": "api.x.ai",
      "path": "/v1/responses",
      "route": "/v1/responses",
      "signedModel": "grok-4.7"
    },
    "kimi-for-coding": {
      "host": "api.kimi.com",
      "path": "/coding/v1/messages",
      "route": "/v1/messages",
      "signedModel": "kimi-for-coding"
    },
    "kimi-k3": {
      "host": "api.kimi.com",
      "path": "/coding/v1/messages",
      "route": "/v1/messages",
      "signedModel": "k3"
    }
  }
});
