# Firebase Notes

Firebase config values (`apiKey`, `projectId`) are public by design; authorization lives entirely in Firestore, Realtime Database, and Storage security rules. The Tea app exposure (July 2025, about 72,000 images) was an unsecured storage bucket, not a code exploit.

Prioritize `firestore.rules`, `storage.rules`, `database.rules.json`, `firebase.json`, Cloud Functions, and any Admin SDK usage.

Check:

- No rule grants `if true` or `.read`/`.write: true` on a path holding user data; `request.auth != null` alone lets every signed-up account read every other account's data.
- Rules bind documents to `request.auth.uid` and validate the fields a client may write (`request.resource.data` keys, types, and ownership fields).
- Storage rules scope objects by user path and size/content-type; uploaded identity documents and selfies are never world-readable.
- Admin SDK service account JSON (`"type": "service_account"`) is absent from the repository and from client bundles; it bypasses all rules.
- Cloud Functions that run with admin privileges validate `context.auth` and the caller's authorization before mutating data.
- Rules are deployed from source control with the emulator rules test suite, not edited in the console.
- App Check is enabled for public-facing projects when abuse of the public config is a concern.

Verification: write a rules unit test with `@firebase/rules-unit-testing` that attempts a cross-user read and write and asserts denial; run it in CI.
