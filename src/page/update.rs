use std::net::SocketAddr;

use rocket::response::stream::{Event, EventStream};
use rocket::tokio;
use rocket::tokio::time::{self, Duration};
use rocket::Shutdown;
use rocket::State;

use crate::adguard::AdGuardHome;
use crate::dropper::FnDropper;
use crate::guard::Authorization;

#[rocket::get("/update")]
pub async fn get<'a>(
	remote_addr: SocketAddr,
	auth: Authorization,
	adguard: &'a State<AdGuardHome>,
	mut shutdown: Shutdown,
) -> EventStream![Event + 'a] {
	let domain = auth.0;
	let ip = remote_addr.ip().to_string();

	let stream = EventStream! {
		let record = adguard.record(&domain, &ip);
		let mut interval = time::interval(Duration::from_secs(10));
		if record.add().await.is_some() {
			let record_dropper = FnDropper::new(record, |record| {
				tokio::spawn(async move {
					_ = record.delete().await;
				});
			});

			loop {
				tokio::select! {
					_ = &mut shutdown => {
						break;
					}
					_ = interval.tick() => {
						yield Event::comment("");
						continue;
					}
				};
			}

			_ = record_dropper.disarm().delete().await;
		}
	};
	stream.heartbeat(None)
}
