Secure Remote Command Execution System
Protocol Specification Document
1. Protocol Overview

The system uses a JSON-based structured communication protocol over a secure TCP (SSL/TLS) connection.

All messages exchanged between client and server must follow this format:
{
  "type": "<message_type>",
  "data": { ... }
}
All communication is encrypted using SSL/TLS.

2. Authentication Phase
2.1 Authentication Request (Client → Server)
{
  "type": "auth",
  "data": {
    "username": "user1",
    "password_hash": "sha256_hash"
  }
}
2.2 Authentication Response (Server → Client)

Success:

{
  "type": "auth_response",
  "data": {
    "status": "success",
    "session_token": "abc123"
  }
}

Failure:

{
  "type": "auth_response",
  "data": {
    "status": "failure",
    "reason": "Invalid credentials"
  }
}
3. Command Execution Phase
3.1 Command Request (Client → Server)
{
  "type": "command",
  "data": {
    "session_token": "abc123",
    "command": "ls"
  }
}
3.2 Command Response (Server → Client)

Success:

{
  "type": "command_output",
  "data": {
    "status": "success",
    "output": "file1\nfile2"
  }
}

Failure:

{
  "type": "command_output",
  "data": {
    "status": "failure",
    "reason": "Unauthorized command"
  }
}
4. Allowed Commands (Whitelist)

Only the following commands are allowed:

ls

pwd

date

whoami

Any other command must be rejected.

5. Error Handling Messages

Invalid JSON:

{
  "type": "error",
  "data": {
    "reason": "Malformed request"
  }
}

Invalid Session:

{
  "type": "error",
  "data": {
    "reason": "Invalid or expired session"
  }
}
6. Session Management Rules

Session token generated after successful authentication

Session expires after timeout (e.g., 5 minutes inactivity)

Token must be included in every command request
