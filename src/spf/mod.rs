//! SPF implements (mostly)parsing for SPF records (RFC https://tools.ietf.org/html/rfc7208#)
//!
//! Some docs on implementation:
//! https://tools.ietf.org/html/rfc7208#section-4

// right now it's not implemented yet

use std::borrow::Cow;
use std::net::{Ipv6Addr, Ipv4Addr};

/// SPFAction decides what to do with message
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum SPFAction {
    Pass,
    // +
    Fail,
    // -
    SoftFail,
    // ~
    Neutral,  // ?
}

impl Default for SPFAction {
    fn default() -> Self {
        Self::Pass
    }
}

pub enum SPFRecordDomain<'a> {
    /// Record is for domain passed in request
    Master,

    /// Record points to some domain
    Given(Cow<'a, [u8]>),
}


/*
pub domain: SPFRecordDomain<'a>,
pub include_a: bool,
pub include_aaaa: bool,
pub include_mx: bool,

pub include_domains: Vec<Cow<'a, [u8]>>,
*/

/// SPFDirectiveKind describes kind of directive that should be used
/// It may be used to determine kin of contents of `SPFDirective`
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum SPFDirectiveKind {
    /// A points to A records of given domain
    A,

    /// AAAA points to AAAA records of given domain
    AAAA,

    /// Ipv4 describes either single IP address or range of ip addresses. for instance: `192.0.2.0/24`
    IPv4,

    /// Ipv6 describes either single IP address or range of ip addresses just like v4 type
    IPv6,
}

// TODO(teawithsand): Enforce Ipv4/Ipv6 restrictions of mask size during deserialization with serde

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct SPFRecord<'a> {
    /// right now the only SPF version is 1
    pub version: u32,

    /// list of directives contained by given spf dns.packet
    pub directives: Vec<SPFDirective<'a>>,
}

/// SPFDirective describe single directive. Many of them may be in single SPFRecord.
///
/// It does not implement support for custom SPF directives.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct SPFDirective<'a> {
    pub qualifier: SPFAction,
    pub mechanism: SPFMechanism<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum SPFMechanism<'a> {
    A(Option<Cow<'a, str>>, Option<u8>),
    // note: there is no quad a in rfc
    AAAA(Option<Cow<'a, str>>, Option<u8>, Option<u8>),
    MX(Option<Cow<'a, str>>, Option<u8>, Option<u8>),

    /// contains ipv4 address and length of address space(in bits) to check
    ///
    /// length should be always less than or equal to `4 * 8 = 32` because there is no more bits in IPv4 addr
    Ipv4(Ipv4Addr, Option<u8>),

    /// contains ipv6 address and length of address space to check
    ///
    ///  length should be always less than or equal to `8 * 16 = 128` because there is no more bits in IPv6 addr
    Ipv6(Ipv6Addr, Option<u8>),

    Ptr(Cow<'a, str>),

    Include(Cow<'a, str>),

    // note: it contains specifier rather than string. It's kind of formatable string,
    Exists(Cow<'a, str>),

    // note: it contains specifier rather than string. It's kind of formatable string,
    Redirect(Cow<'a, str>),

    /// UnknownModifier is modifier which is not specified by rfc7208(https://tools.ietf.org/html/rfc7208)
    UnknownModifier(Cow<'a, str>, Cow<'a, str>),

    /// Exp contains explanation message which may contain format parameters
    Exp(Cow<'a, str>),
    All,
}

#[derive(Debug, From)]
pub enum SPFParseError {
    InvalidChar,
    InvalidStructure,
    InvalidDomain,
}