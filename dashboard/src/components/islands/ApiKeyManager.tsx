/*
File Purpose:
- Interactive API key management UI for create and revoke operations.

Key Security Considerations:
- Displays plaintext key only immediately after generation.
- Uses backend routes that persist hashed values only.

OWASP 2025 Categories Addressed:
- A04, A07, A08
*/

import { useState } from "react";

import { createApiKey, revokeApiKey } from "../../lib/api";

export default function ApiKeyManager() {
  const [createdKey, setCreatedKey] = useState("");
  const [revokeId, setRevokeId] = useState("");
  const [message, setMessage] = useState("");

  async function handleCreate() {
    setMessage("");
    try {
      const record = await createApiKey();
      setCreatedKey(record.key);
      setMessage("API key generated. Save it now; it will not be shown again.");
    } catch {
      setMessage("Unable to generate API key.");
    }
  }

  async function handleRevoke() {
    setMessage("");
    if (!revokeId) {
      setMessage("Provide key id to revoke.");
      return;
    }
    try {
      await revokeApiKey(revokeId);
      setMessage("API key revoked.");
      setRevokeId("");
    } catch {
      setMessage("Unable to revoke API key.");
    }
  }

  return (
    <div>
      <button type="button" onClick={handleCreate}>Generate API key</button>
      {createdKey ? <p style={{ fontFamily: "JetBrains Mono, monospace" }}>{createdKey}</p> : null}
      <div style={{ marginTop: 12 }}>
        <input
          type="text"
          value={revokeId}
          onChange={(e: { target: { value: string } }) => setRevokeId(e.target.value)}
          placeholder="key id"
        />
        <button type="button" onClick={handleRevoke}>Revoke</button>
      </div>
      {message ? <p>{message}</p> : null}
    </div>
  );
}
