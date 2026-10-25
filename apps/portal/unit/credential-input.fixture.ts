import type { ImportCredentialInput } from "../src/import-types";

export const TOKEN_INPUT: ImportCredentialInput = { state: "ready", credentialKind: "bearer_token", inputPolicy: "token_header", fields: [{ name: "token", required: true, secret: true, prompt: "Token", description: "Paste the token value without a Bearer prefix. Existing values cannot be revealed." }] };
export const BASIC_INPUT: ImportCredentialInput = { state: "ready", credentialKind: "basic_api_token", inputPolicy: "http_basic", fields: [{ name: "username", required: true, secret: false, prompt: "Username" }, { name: "token", required: true, secret: true, prompt: "Password or API token" }] };
export const COMMAND_INPUT: ImportCredentialInput = { state: "ready", credentialKind: "basic_api_token", inputPolicy: "command_stdin", fields: [{ name: "username", required: true, secret: false, prompt: "Username" }, { name: "token", required: true, secret: true, prompt: "Token" }] };
