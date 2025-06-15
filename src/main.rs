// use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
// use actix_web::cookie::{Key, SameSite};
// use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
// use serde::Deserialize;
// use tera::Tera;

// // FIX #1a: We need to use the full path to the CsrfMiddleware.
// // The CsrfToken is now handled by its full path in the function signature.
// use actix_csrf::CsrfMiddleware;

// #[derive(Deserialize)]
// struct Transfer {
//     bsb: String,
//     account_no: String,
//     amount: u32,
//     csrf_token: String,
// }

// #[get("/")]
// async fn index(
//     tera: web::Data<Tera>,
//     session: Session,
//     token: actix_csrf::extractor::CsrfToken,
// ) -> impl Responder {
//     if session.get::<String>("user_id").unwrap().is_none() {
//         session.insert("user_id", "12345").unwrap();
//     }

//     let mut context = tera::Context::new();
//     // FIX #2: Access the token string using as_ref().
//     context.insert("csrf_token", token.as_ref());

//     let rendered = tera.render("index.html", &context).unwrap();
//     HttpResponse::Ok().body(rendered)
// }

// #[post("/transfer")]
// async fn transfer(
//     form: web::Form<Transfer>,
//     session: Session,
//     token: actix_csrf::extractor::CsrfToken,
// ) -> impl Responder {
//     // FIX #3: Validate the CSRF token.
//     // Compare the token from the form with the one extracted by actix-csrf.
//     if form.csrf_token != token.as_ref() {
//         return HttpResponse::Forbidden().body("Invalid CSRF token.");
//     }

//     if let Some(user_id) = session.get::<String>("user_id").unwrap() {
//         println!(
//             "SUCCESS: User '{}' transferred ${} to account {}/{}",
//             user_id, form.amount, form.bsb, form.account_no
//         );
//         HttpResponse::Ok().body("Transfer successful!")
//     } else {
//         HttpResponse::Unauthorized().body("You are not logged in.")
//     }
// }

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     let secret_key = Key::generate();

//     HttpServer::new(move || {
//         let tera = Tera::new("templates/**/*").unwrap();

//         App::new()
//             .app_data(web::Data::new(tera))
//             .wrap(
//                 SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
//                     .cookie_same_site(SameSite::Strict)
//                     .build(),
//             )
//             .wrap(CsrfMiddleware::with_rng(rand::thread_rng()))
//             .service(index)
//             .service(transfer)
//     })
//     .bind(("127.0.0.1", 8080))?
//     .run()
//     .await
// }

// VULNERABLE: This code intentionally creates a CSRF vulnerability by not using the actix-csrf middleware and setting SameSite to None.
// use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
// use actix_web::cookie::{Key, SameSite}; // SameSite is needed again
// use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
// use serde::Deserialize;
// use tera::Tera;

// #[derive(Deserialize)]
// struct Transfer {
//     bsb: String,
//     account_no: String,
//     amount: u32,
// }

// #[get("/")]
// async fn index(tera: web::Data<Tera>, session: Session) -> impl Responder {
//     if session.get::<String>("user_id").unwrap().is_none() {
//         session.insert("user_id", "12345").unwrap();
//     }
//     let rendered = tera.render("index.html", &tera::Context::new()).unwrap();
//     HttpResponse::Ok().body(rendered)
// }

// #[post("/transfer")]
// async fn transfer(form: web::Form<Transfer>, session: Session) -> impl Responder {
//     if let Some(user_id) = session.get::<String>("user_id").unwrap() {
//         println!(
//             "SUCCESS: User '{}' transferred ${} to account {}/{}",
//             user_id, form.amount, form.bsb, form.account_no
//         );
//         HttpResponse::Ok().body("Transfer successful!")
//     } else {
//         HttpResponse::Unauthorized().body("You are not logged in.")
//     }
// }

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     let server_addr = "127.0.0.1:8080";
//     let secret_key = Key::generate();

//     println!(
//         "🚀 Starting truly VULNERABLE server at http://{}",
//         server_addr
//     );

//     HttpServer::new(move || {
//         let tera = Tera::new("templates/**/*").unwrap();

//         App::new()
//             .app_data(web::Data::new(tera))
//             // THE FIX: We now explicitly set the SameSite policy to "None"
//             // to override the browser's "Lax" default and create the vulnerability.
//             .wrap(
//                 SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
//                     .cookie_same_site(SameSite::None)
//                     // Note: For SameSite::None to work in production, .cookie_secure(true) is also
//                     // required, which means the site must be served over HTTPS. For local HTTP
//                     // testing, browsers are often more lenient.
//                     .build(),
//             )
//             .service(index)
//             .service(transfer)
//     })
//     .bind(server_addr)?
//     .run()
//     .await
// }

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

    let token: [u8; 32] = rng.r#gen();

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
            "SUCCESS: User '{}' transferred ${} to account {}/{}",
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

    println!(
        "🚀 Starting SECURE server with new library at http://{}",
        server_addr
    );

    HttpServer::new(move || {
        let tera = Tera::new("templates/**/*").unwrap();

        App::new()
            .app_data(web::Data::new(tera))
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
