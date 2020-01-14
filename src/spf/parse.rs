use std::convert::TryFrom;
use std::str::FromStr;

use crate::{SpfAction, SpfDirective, SpfMechanism, SpfRecord};

/// SpfParseError is returned when parsing of given SPF record fails.
#[derive(Debug, From)]
pub enum SpfParseError {
    /// InvalidRecordKind is returned when record does not start with `v=spf1`. Right now `1` is the only SPF version.
    InvalidRecordKind,

    /// Some non-ascii char(or some other illegal one) was found. This is against standard and such record should not be processed anymore.
    InvalidCharFound,

    /// Format for some reason was illegal and text couldn't be parsed
    InvalidFormat,
}

fn parse_addr_spec(text: &str) -> Result<(Option<u8>, Option<u8>), ()> {
    let mut v4_addr_spec = None;
    let mut v6_addr_spec = None;
    if let Some(ipv4_spec) = text.split("/").nth(0) {
        if ipv4_spec.len() > 0 {
            v4_addr_spec = Some(u8::from_str(ipv4_spec)
                .map_err(|_| ())?);
        }
    } else {
        // if there is no '/' in string first result with is equal to text should be returned
        // even if text is empty
        unreachable!("This should not be reached!");
    }
    if let Some(ipv6_spec) = text.split("/").nth(1) {
        if ipv6_spec.len() == 0 {
            return Err(());
        }
        v6_addr_spec = Some(u8::from_str(ipv6_spec)
            .map_err(|_| ())?);
    }
    Ok((v4_addr_spec, v6_addr_spec))
}

fn parse_domain_spec_with_double_cidr_length(text: &str) -> Result<Option<(&str, (Option<u8>, Option<u8>))>, ()> {
    let mut domain = &text[..0];
    if text.len() > 0 && text.as_bytes()[0] == b':' {
        // TODO(teawithsand): implement this
    }
    if text.len() > 0 && text.as_bytes()[0] == b'/' {
        // TODO(teawithsand): implement this
    }
    todo!("Not implemented yet!");
}

impl<'a> SpfDirective<'a> {
    pub fn parse_str(text: &'a str) -> Result<Self, SpfParseError> {
        for c in orig_s.chars() {
            if !c.is_ascii() {
                return Err(SpfParseError::InvalidCharFound);
            }
        }

        if text.len() == 0 {
            return Err(SpfParseError::InvalidFormat);
        }
        let mut text = text;
        let action = match SpfAction::try_from(text.as_bytes()[0]) {
            Ok(a) => {
                text = &text[1..];
                a
            }
            Err(_) => {
                SpfAction::default()
            }
        };
        todo!("Here parse specific directives");
        Ok(Self {
            qualifier: action,
            mechanism: SpfMechanism::All,
        })
    }
}

impl<'a> SpfRecord<'a> {
    pub fn parse_str(orig_s: &'a str) -> Result<Self, SpfParseError> {
        // ensure that all chars are ascii chars
        for c in orig_s.chars() {
            if !c.is_ascii() {
                return Err(SpfParseError::InvalidCharFound);
            }
        }

        let s = orig_s.to_ascii_lowercase(); // all directives are case-insensitive
        // now: All ascii chars are one byte
        // so one may use indices from s to index orig_s and get reference to things like macro directives from there(using borrowing)
        if !s.starts_with("v=spf1") {
            return Err(SpfParseError::InvalidRecordKind);
        }
        let s = s[..6].trim();

        let mut directives = Vec::new();
        for e in s.split(" ") {
            let e = e.trim();
            if e.len() == 0 {
                continue;
            }
        }
        Ok(Self {
            directives,
        })
    }
}

impl<'a> SpfRecord<'a> {
    /// join joins two SPF records into one. It's useful when parsing SPF directives
    /// contained in multiple DNS TXT records.
    pub fn join(self, other: SpfRecord<'a>) -> Self {
        let mut d = self.directives;
        d.extend_from_slice(&other.directives);
        Self {
            directives: d,
        }
    }
}