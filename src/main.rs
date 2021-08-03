
#![feature(proc_macro_hygiene, decl_macro)]

use std::io;
use std::sync::Mutex;
use std::borrow::Cow;

#[macro_use] 
extern crate rocket;

use rocket::{Data, State, Response, http};
use rocket::http::Method;
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;

use rocket_cors;
use rocket_cors::{AllowedHeaders, AllowedOrigins};

extern crate oxide_auth;
extern crate oxide_auth_rocket;

use oxide_auth::endpoint::{OwnerConsent, Solicitation};
use oxide_auth::frontends::simple::endpoint::{
    FnSolicitor, 
    Generic, 
    Vacant,
};
use oxide_auth::primitives::registrar::RegisteredUrl;
use oxide_auth::primitives::prelude::{
    Client, 
    ClientMap, 
    AuthMap, 
    RandomGenerator, 
    TokenMap,
    Registrar,
    Authorizer,
    Issuer
};

use oxide_auth::{ 
    code_grant::extensions::Pkce,
    endpoint::{
        WebRequest,
        AuthorizationFlow,
    },
    frontends::simple::extensions::{AddonList,Extended},
};

use oxide_auth_rocket::{OAuthResponse, OAuthRequest, OAuthFailure};

struct MyState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenMap<RandomGenerator>>,
}



impl MyState {
    pub fn preconfigured() -> Self {
        MyState {
            registrar: Mutex::new(
                vec![Client::public(
                    "LocalClient",
                    RegisteredUrl::Semantic(
                        "http://localhost:3000/".parse().unwrap(),
                    ),
                    "default-scope".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
            ),

            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),

            issuer: Mutex::new(TokenMap::new(RandomGenerator::new(16))),
        }
    }

    pub fn endpoint(
        &self
    ) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_> {
        
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            // Solicitor configured later.
            solicitor: Vacant,
            // Scope configured later.
            scopes: Vacant,
            // `rocket::Response` is `Default`, so we don't need more configuration.
            response: Vacant,
        }
    }
}


#[get("/authorize")]
fn authorize<'r>(
    oauth: OAuthRequest<'r>, state: State<'r, MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    let ep = state.endpoint().with_solicitor(FnSolicitor(consent_form));
    let pkce_extension = Pkce::required();
    let mut extensions = AddonList::new();
    extensions.push_code(pkce_extension);
    let t = Extended::extend_with(ep, extensions);
    
    let mut flow = match AuthorizationFlow::prepare(t){
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    };
    
    flow.execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/authorize?<allow>")]
fn authorize_consent<'r>(
    oauth: OAuthRequest<'r>, allow: Option<bool>, state: State<MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    let allowed = allow.unwrap_or(false);

    let ep = state.endpoint().with_solicitor(
        FnSolicitor(
            move |_: &mut _, grant: Solicitation<'_>| {
                consent_decision(allowed, grant)
            }
        )
    );

    let pkce_extension = Pkce::required();
    let mut extensions = AddonList::new();
    extensions.push_code(pkce_extension);
    let t = Extended::extend_with(ep, extensions);
    
    let mut flow = match AuthorizationFlow::prepare(t){
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    };
    
    flow.execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/token", data = "<body>")]
fn token<'r>(
    mut oauth: OAuthRequest<'r>, body: Data, state: State<MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    oauth.add_body(body);
    state
        .endpoint()
        .access_token_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/refresh", data = "<body>")]
fn refresh<'r>(
    mut oauth: OAuthRequest<'r>, body: Data, state: State<MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    oauth.add_body(body);
    state
        .endpoint()
        .refresh_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

pub fn consent_page_html(
    route: &str, 
    solicitation: Solicitation,
    code_challenge: String,
    code_challenge_method: String
) -> String {
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?{3:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?{3:}&deny=true\">
</form>
</html>"
        };
    }

    let grant = solicitation.pre_grant();
    let state = solicitation.state();

    let mut extra = vec![
        ("response_type", "code"),
        ("client_id", grant.client_id.as_str()),
        ("redirect_uri", grant.redirect_uri.as_str()),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", &code_challenge_method),
    ];

    if let Some(state) = state {
        extra.push(("state", state));
    }
    
    format!(template!(), 
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        serde_urlencoded::to_string(extra).unwrap(),
        &route
    )
}

fn consent_form<'r>(
    req: &mut OAuthRequest<'r>, solicitation: Solicitation,
) -> OwnerConsent<OAuthResponse<'r>> {
    OwnerConsent::InProgress(
        Response::build()
            .status(http::Status::Ok)
            .header(http::ContentType::HTML)
            .sized_body(io::Cursor::new(consent_page_html(
                "/authorize",
                solicitation,
                req.query().unwrap()
                        .unique_value("code_challenge")
                        .unwrap_or(Cow::Borrowed("")).to_string(),
                    req.query().unwrap()
                        .unique_value("code_challenge_method")
                        .unwrap_or(Cow::Borrowed("")).to_string()
            )))
            .finalize()
            .into(),
    )
}

fn consent_decision<'r>(allowed: bool, _: Solicitation) -> OwnerConsent<OAuthResponse<'r>> {
    if allowed {
        OwnerConsent::Authorized("dummy user".into())
    } else {
        OwnerConsent::Denied
    }
}



fn main() -> Result<(), rocket_cors::Error>  {

    let allowed_origins = AllowedOrigins::some_exact(&[
        "http://10.1.10.15:8000",
        "http://127.0.0.1:8000",
        "http://10.0.0.180:8000",
        "http://10.1.10.13:8000",
        "http://10.1.10.17:8000",
        "http://127.0.0.1:8000",
        "http://10.1.10.229",
        "http://localhost:3001",
        "http://localhost:3000",
    ]);

    let cors = rocket_cors::CorsOptions {
        allowed_origins,
        allowed_methods: vec![
            Method::Get, 
            Method::Put, 
            Method::Post
        ].into_iter().map(From::from).collect(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()?;

    rocket::ignite()
        .mount("/static", StaticFiles::from("static"))
        .mount("/", routes![
            authorize, 
            authorize_consent, 
            token,
            refresh,
        ])
        .attach(cors)
        .attach(Template::fairing())
        .manage(MyState::preconfigured())
        .launch();

    Ok(())
}
