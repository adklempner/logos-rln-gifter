//! `auth_type` is a composition: `<scheme>-<authoriser>`.

use std::fmt;

/// The two halves of an `authentication_type`. The scheme name carries no
/// `-`; the authoriser name may (`pow-claim`), so the string splits at the
/// FIRST dash. Names are lowercase ASCII `[a-z0-9-]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthType {
    pub scheme: String,
    pub authoriser: String,
}

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl AuthType {
    pub fn new(scheme: &str, authoriser: &str) -> AuthType {
        AuthType {
            scheme: scheme.to_string(),
            authoriser: authoriser.to_string(),
        }
    }

    pub fn parse(s: &str) -> Result<AuthType, String> {
        let t = s.trim();
        let Some((scheme, authoriser)) = t.split_once('-') else {
            return Err(format!("auth_type {t:?}: expected <scheme>-<authoriser>"));
        };
        if !name_ok(scheme)
            || scheme.contains('-')
            || !name_ok(authoriser)
            || authoriser.ends_with('-')
        {
            return Err(format!(
                "auth_type {t:?}: expected <scheme>-<authoriser>, lowercase [a-z0-9-]"
            ));
        }
        Ok(AuthType::new(scheme, authoriser))
    }

    /// The composed string, `<scheme>-<authoriser>`.
    pub fn name(&self) -> String {
        format!("{}-{}", self.scheme, self.authoriser)
    }

    /// Domain separator of the signed binding: `logos/rln/<name>/2`.
    pub fn domain(&self) -> Vec<u8> {
        format!("logos/rln/{}/2", self.name()).into_bytes()
    }
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.scheme, self.authoriser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_at_the_first_dash_so_the_authoriser_may_carry_dashes() {
        let t = AuthType::parse("logos-pow-claim").unwrap();
        assert_eq!(
            (t.scheme.as_str(), t.authoriser.as_str()),
            ("logos", "pow-claim")
        );
        assert_eq!(t.name(), "logos-pow-claim");
        assert_eq!(t.domain(), b"logos/rln/logos-pow-claim/2");
        let t = AuthType::parse(" eth-allowlist ").unwrap();
        assert_eq!(t.to_string(), "eth-allowlist");
    }

    #[test]
    fn malformed_names_are_errors() {
        for bad in [
            "",
            "eth",
            "-allowlist",
            "eth-",
            "Eth-allowlist",
            "eth allowlist",
            "eth-pow-",
        ] {
            assert!(AuthType::parse(bad).is_err(), "{bad:?}");
        }
    }
}
