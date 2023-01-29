use aes_gcm::{Aes256Gcm, Key};
use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use rocket_dyn_templates::Template;

mod config;
mod dropper;
mod guard;
mod page;

mod adguard;
use adguard::AdGuardHome;

const ASSOCIATED_DATA: &[u8] = b"JSDT DDNS";

#[rocket::launch]
fn rocket() -> _ {
	let rocket = rocket::build();

	let figment = rocket.figment();
	let config: config::Config = figment.extract().expect("config");

	let decoded_secret = Base64.decode(config.token().secret()).unwrap();
	let secret_key = Key::<Aes256Gcm>::clone_from_slice(&decoded_secret);

	let adguard = AdGuardHome::connect(
		config.adguard().base_url(),
		config.adguard().username(),
		config.adguard().password(),
	);

	rocket
		.mount(
			"/",
			rocket::routes![
				page::index::get,
				page::create::get,
				page::create::post,
				page::update::get
			],
		)
		.attach(Template::fairing())
		.manage(secret_key)
		.manage(adguard)
}
