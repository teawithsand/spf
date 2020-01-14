//! SPF implements (mostly)parsing for SPF records (RFC https://tools.ietf.org/html/rfc7208#)
//!
//! Some docs on implementation:
//! https://tools.ietf.org/html/rfc7208#section-4

use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use macro_eval::*;
pub use parse::*;

mod eval;
mod macro_eval;
mod parse;
// TODO(teawithsand): rather than copy this macro from dnsie export it to some common place(?)
/// flag_enum creates enum which may be either known or unknown(yet) flag.
macro_rules! flag_enum {
    (
        $name:ident, $any_name:ident: $val_ty:ty {
             $(
                $variant_name:ident = $variant_val:tt
             ),*
        }

    ) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
        pub enum $name {
            $(
                $variant_name = ($variant_val) as isize
            ),*
        }

        impl $name {
            // deprecate this fn?
            #[inline]
            pub fn try_from_num(n: $val_ty) -> Result<Self, ()> {
                Self::try_from(n)
            }

            #[inline]
            pub fn into_num(self) -> $val_ty {
                self.into()
            }
        }

        impl Into<$val_ty> for $name {
            #[inline]
            fn into(self) -> $val_ty {
                match self {
                    $(
                        Self::$variant_name => $variant_val
                    ),*
                }
            }
        }

        impl TryFrom<$val_ty> for $name {
            type Error = ();

            #[inline]
            fn try_from(val: $val_ty) -> Result<Self, Self::Error> {
                match val {
                    $(
                        $variant_val => Ok(Self::$variant_name),
                    )*
                    _ => Err(()),
                }
            }
        }

        /*
        impl Into<$any_name> for $name {
            fn into(self) -> $any_name {
                $any_name::Known(self)
            }
        }
        */

        impl From<$name> for $any_name {
            fn from(data: $name) -> $any_name {
                $any_name::Known(data)
            }
        }

        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
        pub enum $any_name {
            Known($name),
            Unknown($val_ty)
        }

        impl $any_name {
            pub fn into_canonical(self) -> Self {
                match self {
                    Self::Known(v) => Self::Known(v),
                    Self::Unknown(v) => match $name::try_from(v) {
                        Ok(new_v) => Self::Known(new_v),
                        Err(_) => Self::Unknown(v),
                    }
                }
            }
        }

        impl Into<$val_ty> for $any_name {
            #[inline]
            fn into(self) -> $val_ty {
                match self {
                    Self::Known(v) => v.into(),
                    Self::Unknown(v) => v,
                }
            }
        }

        impl From<$val_ty> for $any_name {
            #[inline]
            fn from(val: $val_ty) -> Self {
                Self::Unknown(val).into_canonical()
            }
        }
    }
}

/// SPFAction decides what to do with message
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum SpfAction {
    // +
    Pass = '+' as isize,

    // -
    Fail = '-' as isize,

    // ~
    SoftFail = '~' as isize,

    // ?
    Neutral = '?' as isize,
}

impl TryFrom<char> for SpfAction {
    type Error = ();

    #[inline]
    fn try_from(value: char) -> Result<Self, Self::Error> {
        match value {
            '+' => Ok(SpfAction::Pass),
            '-' => Ok(SpfAction::Fail),
            '~' => Ok(SpfAction::SoftFail),
            '?' => Ok(SpfAction::Neutral),
            _ => Err(())
        }
    }
}
impl TryFrom<u8> for SpfAction {
    type Error = ();

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_from(value as char)
    }
}

impl Into<char> for SpfAction {
    #[inline]
    fn into(self) -> char {
        match self {
            SpfAction::Pass => '+',
            SpfAction::Fail => '-',
            SpfAction::SoftFail => '~',
            SpfAction::Neutral => '?',
        }
    }
}

impl Into<u8> for SpfAction {
    #[inline]
    fn into(self) -> u8 {
        let c: char = self.into();
        c as u8
    }
}

impl Default for SpfAction {
    fn default() -> Self {
        Self::Pass
    }
}

/// SpfDirectiveKind describes kind of directive that should be used
/// It may be used to determine kin of contents of `SpfDirective`
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum SpfDirectiveKind {
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

/// SpfRecord contains single full result of parsing DNS TXT record which contains spf policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct SpfRecord<'a> {
    /// list of directives contained by given spf dns.packet
    pub directives: Vec<SpfDirective<'a>>,
}

/// SpfDirective describe single directive. Many of them may be in single SpfRecord.
///
/// It does not implement support for custom Spf directives.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct SpfDirective<'a> {
    /// qualifier answers question: What to do when rule matched?
    pub qualifier: SpfAction,

    /// mechanism answers question: Should this qualifier be applied to this sender?
    pub mechanism: SpfMechanism<'a>,
}

/// SpfMechanism describes single rule which may or may not match given sender
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum SpfMechanism<'a> {
    A(Option<Cow<'a, str>>, (Option<u8>, Option<u8>)),
    AAAA(Option<Cow<'a, str>>, (Option<u8>, Option<u8>)),
    MX(Option<Cow<'a, str>>, (Option<u8>, Option<u8>)),

    /// contains ipv4 address and length of address space(in bits) to check
    ///
    /// length should be always less than or equal to `4 * 8 = 32` because there is no more bits in IPv4 addr
    Ipv4(Ipv4Addr, Option<u8>),

    /// contains ipv6 address and length of address space to check
    ///
    ///  length should be always less than or equal to `8 * 16 = 128` because there is no more bits in IPv6 addr
    Ipv6(Ipv6Addr, Option<u8>),

    Include(Cow<'a, str>),

    // note: it contains specifier rather than string. It's kind of formatter string just like printf's first argument.
    Exists(Cow<'a, str>),

    // note: it contains specifier rather than string. It's kind of formatter string just like printf's first argument.
    Redirect(Cow<'a, str>),

    /// UnknownModifier is modifier which is not specified by rfc7208(https://tools.ietf.org/html/rfc7208)
    UnknownModifier(Cow<'a, str>, Cow<'a, str>),

    /// Exp contains explanation message which may contain format parameters
    Exp(Cow<'a, str>),

    All,
}

/// ExternalResourceIdentifier describes which external resource is required to
/// evaluate given directive or mechanism
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum ExternalResourceIdentifier<'a> {
    /// SourceIP is required in order to evaluate given directive
    SourceIP,

    /// SPF record(s) from given domain are required to evaluate this directive
    ///
    /// Used to evaluate `include`
    SPFFromDomain(Cow<'a, str>),

    /// True if domain created as `part_one + "." + part_two` exists or false otherwise.
    ///
    /// Used to evaluate `exists`
    DomainExists(Cow<'a, str>, Cow<'a, str>),
}

/// ExternalResource contains external resources which may be used in order to evaluate
/// SPF directive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct ExternalResourceBag<'a> {
    pub source_ip: Option<IpAddr>,
    pub existence_map: HashMap<Cow<'a, str>, bool>,
    pub domain_record_map: HashMap<Cow<'a, str>, SpfRecord<'a>>,
}

flag_enum! {
    MacroVariable, AnyMacroVariable: u8 {
        Sender = b's',
        LocalPartOfSender = b'l',
        DomainOfSender = b'o',
        Domain = b'd',
        Ip = b'i',
        ValidatedDomainNameOrIp = b'p',
        InAddr = b'v',
        HeloOrEhloDomain = b'h',
        SmtpClientIp = b'c',
        DomainNameOfHostPerformingTheCheck = b'r',
        CurrentTimestamp = b't'
    }
}

impl MacroVariable {
    /// get_valid_symbols returns reference to byte array of all valid formatter symbols
    pub fn get_valid_lowercase_symbols() -> &'static [u8] {
        return &[b's', b'l', b'o', b'd', b'i', b'p', b'h', b'c', b'r', b't', b'v'];
    }
}