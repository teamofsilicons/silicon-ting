//! Type labels may have an operator-assigned prefix; authority always belongs
//! to the canonical Silicon Apps ID. No request can define or change an alias.
use crate::{error::Result, validation as v};
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub struct Prefixes(BTreeMap<String, String>);
impl Prefixes {
    pub fn parse(source: &str) -> anyhow::Result<Self> {
        let value = v::parse(source.as_bytes(), 16384)?;
        let object = value.as_object().expect("strict object parser");
        anyhow::ensure!(
            object.len() <= 128,
            "At most 128 type prefix aliases may be configured"
        );
        let mut aliases = BTreeMap::new();
        for (prefix, owner) in object {
            let owner = owner
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Type prefix owners must be app ID strings"))?;
            anyhow::ensure!(
                v::app_id(prefix) && v::app_id(owner) && prefix != owner,
                "Type prefix aliases need distinct valid prefix and owner app IDs"
            );
            aliases.insert(prefix.clone(), owner.to_owned());
        }
        anyhow::ensure!(
            !aliases.values().any(|owner| aliases.contains_key(owner)),
            "Type prefix aliases cannot be chained or cyclic"
        );
        Ok(Self(aliases))
    }
    pub fn owner<'a>(&'a self, prefix: &'a str) -> &'a str {
        self.0.get(prefix).map(String::as_str).unwrap_or(prefix)
    }
    pub fn owns(&self, app: &str, typ: &str) -> Result<bool> {
        Ok(self.owner(v::type_parts(typ)?.0) == app)
    }
    pub fn aliases(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(prefix, owner)| (prefix.as_str(), owner.as_str()))
    }
}
