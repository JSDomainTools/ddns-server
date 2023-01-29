use core::iter::zip;

use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as UrlBase64, Engine};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::Request;

pub struct Authorization(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorization {
	type Error = ();

	async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		let key = req
			.rocket()
			.state::<Key<Aes256Gcm>>()
			.map(|secret| Key::<Aes256Gcm>::from_slice(secret));
		let Some(key) = key else {
			return Outcome::Failure((Status::InternalServerError, ()))
		};

		let authorization = req.headers().get_one("Authorization");
		let Some(authorization) = authorization else {
			return Outcome::Failure((Status::Forbidden, ()))
		};

		let token = authorization
			.split_once('.')
			.and_then(|(nonce, data)| zip(UrlBase64.decode(nonce), UrlBase64.decode(data)).next());
		let Some((nonce, mut data)) = token else {
			return Outcome::Failure((Status::NotAcceptable, ()))
		};

		match Aes256Gcm::new(key)
			.decrypt_in_place(
				Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from_slice(&nonce),
				crate::ASSOCIATED_DATA,
				&mut data,
			)
			.map_err(|_| Status::Unauthorized)
			.and_then(|_| String::from_utf8(data).map_err(|_| Status::NotAcceptable))
		{
			Ok(data) => Outcome::Success(Self(data)),
			Err(err) => Outcome::Failure((err, ())),
		}
	}
}
