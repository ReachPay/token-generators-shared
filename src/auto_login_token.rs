use encryption::aes::AesKey;
use rust_extensions::date_time::DateTimeAsMicroseconds;

#[derive(::prost::Message)]
pub struct AutoLoginToken {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(int64, tag = "2")]
    pub expires: i64,
}

impl AutoLoginToken {
    pub fn new(client_id: String, expires: i64) -> Self {
        Self { client_id, expires }
    }

    pub fn to_string(&self, key: &AesKey) -> String {
        let mut result = Vec::new();

        prost::Message::encode(self, &mut result).unwrap();
        let result = key.encrypt(result.as_slice());
        hex::encode(result)
    }

    pub fn parse(token: &str, key: &AesKey) -> Option<Self> {
        let encrypted = hex::decode(token);
        if encrypted.is_err() {
            return None;
        }

        let bytes = key.decrypt(encrypted.unwrap().as_slice());
        if bytes.is_err() {
            return None;
        }

        let result: Result<Self, _> = prost::Message::decode(bytes.unwrap().as_slice());

        if result.is_err() {
            return None;
        }

        Some(result.unwrap())
    }

    pub fn is_expired(&self, now: DateTimeAsMicroseconds) -> bool {
        let expires = DateTimeAsMicroseconds::new(self.expires);
        expires.unix_microseconds < now.unix_microseconds
    }
}

#[cfg(test)]
mod tests {
    use encryption::aes::AesKey;

    use crate::AutoLoginToken;

    #[test]
    fn test_issue_prase() {
        let key = AesKey::new(b"123456789012345678901234567890123456789012345678");

        let result = AutoLoginToken::parse("565df043cc118ebde04d2bbc07588ee215b080cd47beed6d488fcc4dbf6421045307abf1863773844989f708c28b38d9", &key);

        assert!(result.is_some());
    }
}
