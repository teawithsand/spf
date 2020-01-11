# spf

[documentation](https://docs.rs/dnsie)

spf crate implements SPF policy parsing and execution.
It is able to tell if given sender is valid or not using given SPF policy
and parse SPF's string macro format(yes SPF has one) in order to print pretty error message.

# RFC
It implements [RFC 7208](https://tools.ietf.org/html/rfc7208).
It does not implement obsolete [RFC 4408](https://tools.ietf.org/html/rfc7208)