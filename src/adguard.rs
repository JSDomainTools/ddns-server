use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use rocket::serde::Serialize;

pub struct AdGuardHome {
	url: String,
	authorization: String,
	active_domains: Arc<Mutex<HashSet<String>>>,
}

impl AdGuardHome {
	#[must_use]
	pub fn connect(url: &str, username: &str, password: &str) -> Self {
		Self {
			url: url.to_owned(),
			authorization: format!(
				"Basic {}",
				Base64.encode(format!("{}:{}", username, password))
			),
			active_domains: Arc::new(Mutex::new(HashSet::new())),
		}
	}

	#[must_use]
	pub fn record(&self, domain: &str, answer: &str) -> DynDnsRecord {
		DynDnsRecord::new(
			&self.url,
			&self.authorization,
			domain,
			answer,
			&self.active_domains,
		)
	}
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct RewriteBody<'a> {
	domain: &'a str,
	answer: &'a str,
}

enum DynDnsOp {
	Add,
	Delete,
}

impl DynDnsOp {
	fn path(&self) -> &'static str {
		match self {
			DynDnsOp::Add => "add",
			DynDnsOp::Delete => "delete",
		}
	}
}

pub struct DynDnsRecord {
	url: String,
	authorization: String,
	domain: String,
	answer: String,
	active_domains: Arc<Mutex<HashSet<String>>>,
}

impl DynDnsRecord {
	#[must_use]
	fn new(
		url: &str,
		authorization: &str,
		domain: &str,
		answer: &str,
		active_domains: &Arc<Mutex<HashSet<String>>>,
	) -> Self {
		Self {
			url: url.to_owned(),
			authorization: authorization.to_owned(),
			domain: domain.to_owned(),
			answer: answer.to_owned(),
			active_domains: Arc::clone(active_domains),
		}
	}

	#[must_use]
	pub async fn add(&self) -> Option<()> {
		Self::apply_rewrite(
			&self.url,
			&self.authorization,
			&self.domain,
			&self.answer,
			DynDnsOp::Add,
			&self.active_domains,
		)
		.await
	}

	#[must_use]
	pub async fn delete(&self) -> Option<()> {
		Self::apply_rewrite(
			&self.url,
			&self.authorization,
			&self.domain,
			&self.answer,
			DynDnsOp::Delete,
			&self.active_domains,
		)
		.await
	}
}

impl DynDnsRecord {
	#[must_use]
	async fn apply_rewrite(
		url: &str,
		authorization: &str,
		domain: &str,
		answer: &str,
		op: DynDnsOp,
		active_domains: &Arc<Mutex<HashSet<String>>>,
	) -> Option<()> {
		active_domains
			.lock()
			.map(|mut guard| match op {
				DynDnsOp::Add => {
					if guard.contains(domain) {
						None
					} else {
						guard.insert(domain.to_owned());
						Some(())
					}
				}
				DynDnsOp::Delete => {
					guard.remove(domain);
					Some(())
				}
			})
			.map_err(|err| eprintln!("active_domains {}: {err}", op.path()))
			.ok()??;

		let response = reqwest::Client::new()
			.post(format!("{}/control/rewrite/{}", url, op.path()))
			.header("Authorization", authorization)
			.json(&RewriteBody { domain, answer })
			.send()
			.await
			.map_err(|err| eprintln!("reqwest post {}: {err}", op.path()))
			.ok()?;

		let status = response.status();
		if status.is_success() {
			Some(())
		} else {
			eprintln!("reqwest status: {status}");
			active_domains
				.lock()
				.map(|mut guard| match op {
					DynDnsOp::Add => {
						guard.remove(domain);
					}
					DynDnsOp::Delete => (),
				})
				.map_err(|err| eprintln!("active_domains {}: {err}", op.path()))
				.ok()?;
			None
		}
	}
}
