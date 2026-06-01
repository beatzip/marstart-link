use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    // другие поля профиля
}

pub fn load_profile(id: &str) -> Result<Profile, String> {
    // Заглушка — в реальности загружай из файла/базы
    Ok(Profile {
        id: id.to_string(),
    })
}
