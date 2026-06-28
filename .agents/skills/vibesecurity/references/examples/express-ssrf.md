# Express SSRF

Vulnerable pattern:

```js
app.get("/preview", async (req, res) => {
  const body = await fetch(req.query.url).then((r) => r.text());
  res.send(body);
});
```

Safe pattern:

```js
app.get("/preview", async (req, res) => {
  const url = parseAllowedPublicUrl(req.query.url);
  const body = await fetch(url, { redirect: "error" }).then((r) => r.text());
  res.send(body);
});
```

Review lesson: user-controlled URL fetches need scheme, host, IP range, redirect, timeout, and response-size controls.
