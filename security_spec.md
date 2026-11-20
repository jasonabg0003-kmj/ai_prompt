# Security Specification — 나의 AI 프롬프트 창고 (공개 보안 규칙)

## 1. Access Model & Data Invariants
- **Public Read (`prompts` only)**: Any visitor (including unauthenticated guests) can read (`get`, `list`) documents in `/prompts/{promptId}`.
- **Default-Deny All Other Collections**: All other collections and paths are strictly denied (`allow read, write: if false;`).
- **Admin-Only Write (`jasonabg0003@gmail.com`)**: Only a Google-authenticated user with `email == 'jasonabg0003@gmail.com'` and `email_verified == true` can `create`, `update`, or `delete` documents in `/prompts/{promptId}`.
- **Field Bounds**:
  - `title`: string, `1 <= size <= 100`
  - `category`: string in `['사진 합성', '스타일 변환', '캐릭터·포스터']`
  - `content`: string, `1 <= size <= 10000`
  - `createdAt`: timestamp (`== request.time` on `create`, immutable on `update`)
  - Strict keys: `['title', 'category', 'content', 'createdAt']`

## 2. Adversarial "Dirty Dozen" Payloads (Expected: PERMISSION_DENIED)
1. **Guest Create**: Unauthenticated user calls `addDoc` on `prompts` -> Rejected by `isAdmin()`.
2. **Guest Update**: Unauthenticated user calls `updateDoc` on `prompts` -> Rejected by `isAdmin()`.
3. **Guest Delete**: Unauthenticated user calls `deleteDoc` on `prompts` -> Rejected by `isAdmin()`.
4. **Non-Admin User Write**: Signed-in user `other@gmail.com` tries to write `prompts` -> Rejected by `isAdmin()`.
5. **Unverified Admin Email Spoof**: Token with `email_verified == false` -> Rejected by `email_verified == true`.
6. **Other Collection Read**: Any user reads `/users/1` or `/test/connection` -> Rejected by global default-deny.
7. **Other Collection Write**: Even admin tries to write `/other/doc1` -> Rejected by global default-deny.
8. **Oversized Title (>100 chars)**: Admin sends 101-char `title` -> Rejected by `title.size() <= 100`.
9. **Oversized Content (>10000 chars)**: Admin sends 10,001-char `content` -> Rejected by `content.size() <= 10000`.
10. **Shadow Field Injection**: Admin sends `{ ..., extra: true }` -> Rejected by `hasOnly`.
11. **Timestamp Forgery / Mutation**: Client tries to forge `createdAt` or mutate it on update -> Rejected.
12. **Invalid Category or Document ID**: Unknown category or invalid ID characters -> Rejected.
