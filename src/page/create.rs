use aes_gcm::aead::{AeadMutInPlace, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use base64::{
	engine::general_purpose::STANDARD as Base64,
	engine::general_purpose::URL_SAFE_NO_PAD as UrlBase64, Engine,
};
use rocket::form::{Form, FromForm};
use rocket::http::Status;
use rocket_dyn_templates::{context, Template};

#[derive(FromForm)]
pub struct Create<'r> {
	domain: &'r str,
	secret: &'r str,
}

#[rocket::get("/create")]
pub async fn get() -> Template {
	Template::render("create", context! {})
}

#[rocket::post("/create", data = "<form>")]
pub async fn post(form: Form<Create<'_>>) -> Result<Template, Status> {
	let secret = Base64.decode(form.secret).map_err(|err| {
		eprintln!("Base64.decode: {err}");
		Status::BadRequest
	})?;

	let mut data = form.domain.as_bytes().to_owned();
	let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

	Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&secret))
		.encrypt_in_place(&nonce, crate::ASSOCIATED_DATA, &mut data)
		.map_err(|err| {
			eprintln!("encrypt_in_place: {err}");
			Status::InternalServerError
		})?;

	let token = format!("{}.{}", UrlBase64.encode(nonce), UrlBase64.encode(&data));
	Ok(Template::render(
		"create",
		context! {
			token,
		},
	))
}
