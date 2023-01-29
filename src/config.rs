use rocket::serde::Deserialize;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Config {
	token: ConfigToken,
	adguard: ConfigAdGuard,
}

impl Config {
	pub fn token(&self) -> &ConfigToken {
		&self.token
	}

	pub fn adguard(&self) -> &ConfigAdGuard {
		&self.adguard
	}
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ConfigToken {
	secret: String,
}

impl ConfigToken {
	pub fn secret(&self) -> &str {
		&self.secret
	}
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ConfigAdGuard {
	base_url: String,
	username: String,
	password: String,
}

impl ConfigAdGuard {
	pub fn base_url(&self) -> &str {
		&self.base_url
	}

	pub fn username(&self) -> &str {
		&self.username
	}

	pub fn password(&self) -> &str {
		&self.password
	}
}
