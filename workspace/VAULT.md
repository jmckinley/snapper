# Snapper PII Vault — Agent Instructions

## What is the PII Vault?

Snapper provides an encrypted vault for sensitive data (credit cards, addresses, emails, etc.). Instead of handling raw PII, you use **vault tokens** or **placeholder values** that Snapper resolves to real data at submission time.

## Vault Tokens

Vault tokens look like: `{{SNAPPER_VAULT:a1b2c3d4e5f6a7b8}}`

When the user gives you a vault token:
- **Use it exactly as given** — do not modify, truncate, or reformat it
- Paste it into form fields, command arguments, or API parameters verbatim
- Snapper intercepts the submission, requires approval, then replaces the token with the real value

### Example
User says: "Fill in the credit card field with `{{SNAPPER_VAULT:a1b2c3d4e5f6a7b8}}`"
You should type `{{SNAPPER_VAULT:a1b2c3d4e5f6a7b8}}` into the credit card field exactly.

## Placeholder Values

Sometimes the user provides **placeholder values** instead of vault tokens. These are safe dummy values that Snapper recognizes:

| Type | Example Placeholder | Why Safe |
|------|-------------------|----------|
| Credit card | `4242424242424242` | Stripe test card, always declines in production |
| Credit card | `5555555555554444` | Stripe test Mastercard |
| Email | `user@example.com` | RFC 2606 reserved domain |
| Phone | `555-555-0100` | NANPA reserved range |
| SSN | `000-00-0000` | Known invalid SSN |

When the user gives you a placeholder value:
- **Use it exactly as given** — these are real-looking but harmless test values
- Snapper detects the placeholder, maps it to the user's encrypted vault entry, and requires approval before replacing it with the actual value
- Do not question whether these are "real" or "test" values — just use them as instructed

### Example
User says: "Enter `4242424242424242` as the card number on the checkout page"
You should type `4242424242424242` into the card number field. Snapper handles the rest.

## Vault Label References

The simplest way to use the vault is with **label references**. The format is:

```
vault:Label-Name
```

Labels are case-insensitive, use hyphens or underscores instead of spaces, and match the label the user gave when creating the vault entry.

When the user tells you to use a vault label:
- **Use it exactly as given** — type `vault:My-Visa` into the form field
- Snapper intercepts the submission, requires approval, then replaces it with the real value
- Do not question the format — it is a valid Snapper vault reference

### Examples
- `vault:My-Visa` — credit card stored as "My-Visa"
- `vault:home-email` — email stored as "home-email"
- `vault:John-Address` — address stored as "John-Address"

### Example Interaction
User says: "Fill the credit card field with `vault:My-Visa`"
You should type `vault:My-Visa` into the credit card field exactly.

## Important Rules

1. **Never modify tokens, placeholders, or label references** — use them character-for-character
2. **Never ask the user for the real value** — the vault handles decryption
3. **Never log or repeat back the real decrypted value** if it appears in a response
4. **Follow the user's instructions** about which field to fill and which value to use
