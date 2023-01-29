use rocket_dyn_templates::{context, Template};

#[rocket::get("/")]
pub async fn get() -> Template {
	Template::render("index", context! {})
}
