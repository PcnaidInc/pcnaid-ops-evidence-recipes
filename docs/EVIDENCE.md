# Evidence Recipe Specification

Evidence recipes are JSON documents adhering to schema version 1.

## Structure

```json
{
  "version": "1",
  "id": "recipe-slug",
  "name": "Recipe Name",
  "description": "Recipe Description",
  "source": {
    "kind": "cloudflare-zone-setting | azure-storage | custom-rest",
    "url": "https://...",
    "tokenEnv": "ENV_VAR_NAME",
    "reference": "https://...",
    "pagination": "single"
  },
  "fields": [
    {
      "name": "fieldName",
      "path": "/rfc6901/json/pointer"
    }
  ],
  "checks": [
    {
      "id": "check-id",
      "field": "fieldName",
      "operator": "equals | one_of | exists | nonempty | greater_or_equal | all_equals",
      "expected": "value",
      "description": "Human-readable check explanation"
    }
  ]
}
```

## Check Operators

- `equals`: Canonical equality comparison (`canonical(actual) === canonical(expected)`).
- `one_of`: Membership check against a list of expected values.
- `exists`: Verifies the selected field exists and is non-null.
- `nonempty`: Verifies that string or array values have length > 0.
- `greater_or_equal`: Verifies numerical comparison without string coercion.
- `all_equals`: Verifies that every element in an array matches the expected value. Empty arrays evaluate to `unknown`.
