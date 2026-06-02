use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
}

pub fn load_profile(id: &str) -> Result<Profile, String> {
    Ok(Profile { id: id.to_string() })
}
