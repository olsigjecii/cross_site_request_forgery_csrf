# Demo for CSRF

## test the exploit

```bash
cargo run
```

What to do now:
Important: You might need to clear your browser's cookies for 127.0.0.1 to make sure you get the new SameSite=None cookie.
Visit http://127.0.0.1:8080.
Open malicious.html from the file system.
This time, because the cookie is explicitly marked as SameSite=None, the browser will send it with the cross-site POST request, your server will see the session, and you will finally see the "SUCCESS" message in your console.
