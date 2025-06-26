# Rust and Actix Web: A Lesson in Cross-Site Request Forgery (CSRF)

This project is a hands-on lesson demonstrating how to identify, exploit, and prevent Cross-Site Request Forgery (CSRF) vulnerabilities in a Rust web application built with the Actix Web framework.

Lesson Summary
Cross-Site Request Forgery (CSRF) is an attack that tricks an authenticated user into performing an unwanted action on a web application. The attack works by forcing the user's browser to send a malicious request to the target application, which the browser automatically includes the user's session cookies with. A vulnerable application, relying solely on these cookies for authentication, will process the fraudulent request as if the user initiated it legitimately.

In this lesson, we build a simple "Saturn Bank" application with two versions:

A vulnerable version that only uses session cookies, making it susceptible to a CSRF attack.
A secure version that implements a defense-in-depth strategy using two primary techniques:
The Synchronizer Token Pattern: Generating a unique, secret token for each session and validating it on every sensitive request.
SameSite Cookies: Setting the SameSite=Strict attribute on session cookies to instruct the browser not to send them on cross-site requests.
Project Structure
.
├── Cargo.toml
├── src
│   └── main.rs
└── templates
    └── index.html
You will also create a malicious.html file locally to perform the attack.

Setup Instructions
Clone or Download: Get the project files onto your local machine.
Install Rust: If you don't have it already, install the Rust toolchain from rustup.rs.
Build the Project: Navigate to the project directory in your terminal and run the build command. This will download and compile all the necessary dependencies.
Bash

cargo build
Part 1: Demonstrating the Vulnerability
First, we will run the intentionally vulnerable version of the application to see the CSRF attack in action.

Code for the Vulnerable Application
To perform this test, ensure your project files match the code below.

&lt;details>
&lt;summary>Click to see the vulnerable &lt;code>Cargo.toml&lt;/code>&lt;/summary>

Ini, TOML

[package]
name = "csrf-lesson-rust"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
actix-session = { version = "0.8", features = ["cookie-session"] }
serde = { version = "1.0", features = ["derive"] }
tera = "1"
rand = "0.8"
&lt;/details>

&lt;details>
&lt;summary>Click to see the vulnerable &lt;code>src/main.rs&lt;/code>&lt;/summary>

Rust

use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::cookie::{Key, SameSite};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use tera::Tera;

#[derive(Deserialize)]
struct Transfer {
    bsb: String,
    account_no: String,
    amount: u32,
}

#[get("/")]
async fn index(tera: web::Data<Tera>, session: Session) -> impl Responder {
    if session.get::<String>("user_id").unwrap().is_none() {
        session.insert("user_id", "12345").unwrap();
    }
    let rendered = tera.render("index.html", &tera::Context::new()).unwrap();
    HttpResponse::Ok().body(rendered)
}

#[post("/transfer")]
async fn transfer(form: web::Form<Transfer>, session: Session) -> impl Responder {
    if let Some(user_id) = session.get::<String>("user_id").unwrap() {
        println!(
            "✅ [VULNERABLE] SUCCESS: User '{}' transferred ${} to account {}/{}",
            user_id, form.amount, form.bsb, form.account_no
        );
        HttpResponse::Ok().body("Transfer successful!")
    } else {
        HttpResponse::Unauthorized().body("You are not logged in.")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let server_addr = "127.0.0.1:8080";
    let secret_key = Key::generate();

    println!("🚀 Starting VULNERABLE server at http://{}", server_addr);

    HttpServer::new(move || {
        let tera = Tera::new("templates/**/*").unwrap();
        App::new()
            .app_data(web::Data::new(tera))
            // VULNERABLE: Explicitly set SameSite=None to override modern browser defaults.
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_same_site(SameSite::None)
                    .cookie_secure(false) // Allow over HTTP for local testing
                    .build(),
            )
            .service(index)
            .service(transfer)
    })
    .bind(server_addr)?
    .run()
    .await
}
&lt;/details>

&lt;details>
&lt;summary>Click to see the vulnerable &lt;code>templates/index.html&lt;/code>&lt;/summary>

HTML

<!DOCTYPE html>
<html>
<head>
    <title>Saturn Bank (Vulnerable)</title>
</head>
<body>
    <h1>Welcome to the Vulnerable Saturn Bank</h1>
    <h2>Transfer Funds</h2>
    <form action="/transfer" method="POST">
        <label for="bsb">BSB:</label><br>
        <input type="text" id="bsb" name="bsb"><br>
        <label for="account_no">Account No:</label><br>
        <input type="text" id="account_no" name="account_no"><br>
        <label for="amount">Amount:</label><br>
        <input type="text" id="amount" name="amount"><br><br>
        <input type="submit" value="Transfer">
    </form>
</body>
</html>
&lt;/details>

Steps to Exploit
Run the Vulnerable Server:

Bash

cargo run
Log In: Open your web browser and navigate to http://127.0.0.1:8080. This action sets the session cookie in your browser.

Create the Attacker's Page: Create a new file named malicious.html anywhere on your computer and paste the following content into it:

HTML

<html>
 <body>
   <h3>Congrats! You've won a free prize!</h3>
   <form action="http://127.0.0.1:8080/transfer" method="POST" id="csrf-form">
     <input type="hidden" name="bsb" value="666-666" />
     <input type="hidden" name="account_no" value="987654321" />
     <input type="hidden" name="amount" value="1000" />
   </form>
   <script>
     document.getElementById('csrf-form').submit();
   </script>
 </body>
</html>
Spring the Trap: In a new tab in the same browser, open the malicious.html file you just created (you can often just double-click it).

Check the Result: Look at the terminal where your server is running. You will see the success message printed, confirming that a fraudulent transfer was processed without your consent.

✅ [VULNERABLE] SUCCESS: User '12345' transferred $1000 to account 666-666/987654321
Part 2: Demonstrating the Mitigation
Now, we will update the application with our security fixes and prove that the same attack no longer works. We will use the final, manual implementation you created.

Code for the Secure Application
Update your project files to match the secure code below.

&lt;details>
&lt;summary>Click to see the secure &lt;code>Cargo.toml&lt;/code>&lt;/summary>

Ini, TOML

[package]
name = "csrf-lesson-rust"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
actix-session = { version = "0.8", features = ["cookie-session"] }
serde = { version = "1.0", features = ["derive"] }
tera = "1"
rand = "0.8"
base64 = "0.21"
&lt;/details>

&lt;details>
&lt;summary>Click to see the secure &lt;code>src/main.rs&lt;/code>&lt;/summary>

Rust

use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::cookie::{Key, SameSite};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use serde::Deserialize;
use tera::Tera;

#[derive(Deserialize)]
struct Transfer {
    bsb: String,
    account_no: String,
    amount: u32,
    csrf_token: String,
}

#[get("/")]
async fn index(tera: web::Data<Tera>, session: Session) -> impl Responder {
    if session.get::<String>("user_id").unwrap().is_none() {
        session.insert("user_id", "12345").unwrap();
    }

    let mut rng = rand::thread_rng();
    let token: [u8; 32] = rng.gen();
    let token_str = general_purpose::URL_SAFE.encode(&token);
    session.insert("csrf_token", &token_str).unwrap();

    let mut context = tera::Context::new();
    context.insert("csrf_token", &token_str);

    match tera.render("index.html", &context) {
        Ok(rendered_body) => HttpResponse::Ok().body(rendered_body),
        Err(e) => {
            eprintln!("[SERVER ERROR] Failed to render template: {}", e);
            HttpResponse::InternalServerError().body("An error occurred. Check server logs.")
        }
    }
}

#[post("/transfer")]
async fn transfer(form: web::Form<Transfer>, session: Session) -> impl Responder {
    if let Some(token) = session.get::<String>("csrf_token").unwrap() {
        if form.csrf_token != token {
            return HttpResponse::Forbidden().body("Invalid CSRF token.");
        }
    } else {
        return HttpResponse::Forbidden().body("CSRF token not found in session.");
    }

    if let Some(user_id) = session.get::<String>("user_id").unwrap() {
        println!(
            "✅ [SECURE] SUCCESS: User '{}' transferred ${} to account {}/{}",
            user_id, form.amount, form.bsb, form.account_no
        );
        HttpResponse::Ok().body("Transfer successful!")
    } else {
        HttpResponse::Unauthorized().body("You are not logged in.")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let server_addr = "127.0.0.1:8080";
    let secret_key = Key::generate();

    println!("🚀 Starting SECURE server at http://{}", server_addr);

    HttpServer::new(move || {
        let tera = Tera::new("templates/**/*").unwrap();
        App::new()
            .app_data(web::Data::new(tera))
            // SECURE: Set SameSite=Strict and add CSRF token validation.
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_same_site(SameSite::Strict)
                    .build(),
            )
            .service(index)
            .service(transfer)
    })
    .bind(server_addr)?
    .run()
    .await
}
&lt;/details>

&lt;details>
&lt;summary>Click to see the secure &lt;code>templates/index.html&lt;/code>&lt;/summary>

HTML

<!DOCTYPE html>
<html>
<head>
    <title>Saturn Bank (Secure)</title>
</head>
<body>
    <h1>Welcome to the Secure Saturn Bank</h1>
    <h2>Transfer Funds</h2>
    <form action="/transfer" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

        <label for="bsb">BSB:</label><br>
        <input type="text" id="bsb" name="bsb"><br>
        <label for="account_no">Account No:</label><br>
        <input type="text" id="account_no" name="account_no"><br>
        <label for="amount">Amount:</label><br>
        <input type="text" id="amount" name="amount"><br><br>
        <input type="submit" value="Transfer">
    </form>
</body>
</html>
&lt;/details>

Verifying the Fix
Run the Secure Server:

Bash

cargo run
Try the Exploit Again: Open malicious.html in your browser again.

Check the Result: Look at your server's terminal. You will see no "SUCCESS" message. The attack was blocked. In your browser's Developer Tools (F12) under the Network tab, you will likely see the request to /transfer failed with a 403 Forbidden status.

Test Legitimate Use: Go to http://127.0.0.1:8080. Fill out the form with valid data and click "Transfer". Check your terminal again. You will see the ✅ [SECURE] SUCCESS... message, proving that the application works as intended for legitimate users.

Key Takeaways
Defense-in-Depth: Combining application-level defenses (CSRF Tokens) and browser-level defenses (SameSite cookies) provides robust protection.
Manual vs. Library: Understanding how to implement the logic manually provides deep insight into how security libraries work under the hood.
Trust Nothing: Never trust a request just because it includes a valid session cookie. Always require an additional, state-changing-specific token for sensitive actions.