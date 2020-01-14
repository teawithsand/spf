//! Module responsible for evaluating SPF error/domain existence macros.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::num::ParseIntError;
use std::str::FromStr;

use crate::spf::{AnyMacroVariable, MacroVariable};

#[derive(Debug, From)]
pub enum MacroEvaluationError {
    ParsingSyntaxError,

    /// UnknownVariable is returned when `EvaluationContext` was not able to find value for given variable.
    UnknownVariable(AnyMacroVariable),

    ParseIntError(ParseIntError),
}

/// EvaluationContext provides variables required to format macro.
pub trait EvaluationContext {
    /// according to rfc valid tokens are:
    fn provide_data(&self, v: MacroVariable) -> Result<Cow<str>, MacroEvaluationError>;
}

impl<'a, S> EvaluationContext for HashMap<MacroVariable, S>
    where S: AsRef<str>
{
    fn provide_data(&self, var: MacroVariable) -> Result<Cow<str>, MacroEvaluationError> {
        self.get(&var)
            .map(|val| val.as_ref())
            .map(|val| Cow::Borrowed(val))
            .ok_or(MacroEvaluationError::UnknownVariable(AnyMacroVariable::from(var)))
    }
}

/// SortedVectorEvaluationContext is wrapper which may wrap vector(or slice reference) of `(MacroVariable, T)`
/// so it can be used as macro variable provider
///
/// # Sorting
/// It can take advantage of sorting(if given input collection is sorted).
/// When collection is sorted binary search is performed.
/// ### Notes
/// Sorting if(any) has to be ascending by `MacroVariable` parameter
/// (for all pairs `(A[i], A[i+x])` where `x > 0` condition `A[i] <= A[i+x]` must be true where `A` is array of `MacroVariable`s)
/// If there are many pairs with same first parameter any of them may be used(behaviour kinda is undefined, preferably do not do that).
pub struct VecEvaluationContext<'a, T>(bool, Cow<'a, [(MacroVariable, T)]>)
    where [(MacroVariable, T)]: Clone
;

impl<'a, T> Into<Cow<'a, [(MacroVariable, T)]>> for VecEvaluationContext<'a, T>
    where [(MacroVariable, T)]: Clone
{
    #[inline]
    fn into(self) -> Cow<'a, [(MacroVariable, T)]> {
        self.1
    }
}

impl<'a, T> From<Cow<'a, [(MacroVariable, T)]>> for VecEvaluationContext<'a, T>
    where [(MacroVariable, T)]: Clone
{
    fn from(data: Cow<'a, [(MacroVariable, T)]>) -> Self {
        // can't we just sort here?
        let sorted = data.windows(2)
            .map(|a| (a[0].0, a[1].0))
            .all(|(v1, v2)| v1 <= v2);

        VecEvaluationContext(sorted, data)
    }
}


impl<'a, T> EvaluationContext for VecEvaluationContext<'a, T>
    where
        T: AsRef<str>,
        [(MacroVariable, T)]: Clone
{
    fn provide_data(&self, v: MacroVariable) -> Result<Cow<str>, MacroEvaluationError> {
        if self.0 {
            if let Ok(idx) = self.1.binary_search_by_key(&v, |k| k.0) {
                Ok(Cow::Borrowed(self.1[idx].1.as_ref()))
            } else {
                Err(MacroEvaluationError::UnknownVariable(AnyMacroVariable::from(v)))
            }
        } else {
            if let Some((_, v)) = self.1.iter().find(|(k, _)| *k == v) {
                Ok(Cow::Borrowed(v.as_ref()))
            } else {
                Err(MacroEvaluationError::UnknownVariable(AnyMacroVariable::from(v)))
            }
        }
    }
}

impl<'a, S> EvaluationContext for &HashMap<MacroVariable, S>
    where S: AsRef<str>
{
    fn provide_data(&self, var: MacroVariable) -> Result<Cow<str>, MacroEvaluationError> {
        self.get(&var)
            .map(|val| val.as_ref())
            .map(|val| Cow::Borrowed(val))
            .ok_or(MacroEvaluationError::UnknownVariable(AnyMacroVariable::from(var)))
    }
}

struct MacroEvaluator<'a, E> {
    ctx: E,
    res: String,
    input: &'a str,
}

impl<'a, E> MacroEvaluator<'a, E>
    where E: EvaluationContext
{
    fn put_formatter(&mut self, letter: u8, reverse: bool, do_urlencode: bool, label_count: Option<usize>, delimiter: HashSet<char>) -> Result<(), MacroEvaluationError> {
        let text = self.ctx.provide_data(
            MacroVariable::try_from(letter)
                .map_err(|_| AnyMacroVariable::from(letter))?
        )?;
        let i = text.split(|c| {
            if delimiter.is_empty() {
                c == '.'
            } else {
                delimiter.contains(&c)
            }
        });
        let new_text = if reverse {
            i
                .rev()
                .take(label_count.unwrap_or(std::usize::MAX))
                .collect::<Vec<_>>()
                .join(".")
        } else {
            i
                .take(label_count.unwrap_or(std::usize::MAX))
                .collect::<Vec<_>>()
                .join(".")
        };
        if do_urlencode {
            for c in url::form_urlencoded::byte_serialize(new_text.as_bytes()) {
                self.res.push_str(c);
            }
        } else {
            self.res.push_str(&new_text);
        }
        Ok(())
    }

    /// returns offset and number read. If there is no number offset is always zero.
    fn read_number(mut input_data: &str) -> Result<(usize, Option<usize>), MacroEvaluationError> {
        let mut offset = 0;
        let original_data = input_data;
        loop {
            if input_data.len() == 0 {
                return Err(MacroEvaluationError::ParsingSyntaxError);
            }
            let c = input_data.chars().nth(0).unwrap();
            input_data = &input_data[c.len_utf8()..];
            if c.is_ascii_digit() {
                offset += c.len_utf8();
            } else {
                let data = &original_data[..offset];
                return if data.len() == 0 {
                    Ok((offset, None))
                } else {
                    let res = Ok((offset, Some(usize::from_str(data)?)));
                    res
                };
            }
        }
    }

    fn consume_after_percentage_token(&mut self) -> Result<(), MacroEvaluationError> {
        let mut state = 0;

        let mut letter = None;
        let mut is_reverse = false;
        let mut delimiter = HashSet::new();
        let mut number_data = None;

        let mut do_urlencode = false;

        let mut offset = 0;

        let mut data = self.input;
        loop {
            if data.len() == 0 {
                return Err(MacroEvaluationError::ParsingSyntaxError);
            }
            let c = data.chars().nth(0).unwrap();
            offset += c.len_utf8();
            data = &data[c.len_utf8()..];

            match (state, c) {
                (0, '{') => {
                    state = 1;
                }
                (0, '_') => {
                    self.res.push(' ');
                    break;
                }
                (0, '-') => {
                    self.res.push_str("%20");
                    break;
                }
                (0, '%') => {
                    self.res.push('%');
                    break;
                }
                (0, l) if l <= std::u8::MAX as char && MacroVariable::get_valid_lowercase_symbols().contains(&(l.to_ascii_lowercase() as u8)) => {
                    letter = Some(l.to_ascii_lowercase());
                    // uppercase macros are expanded like lowercase but are urlencoded
                    do_urlencode = l.is_ascii_uppercase();
                    break;
                }
                // if one of allowed modifiers
                (1, l) if l <= std::u8::MAX as char && MacroVariable::get_valid_lowercase_symbols().contains(&(l.to_ascii_lowercase() as u8)) => {
                    letter = Some(l.to_ascii_lowercase());
                    // uppercase macros are expanded like lowercase but are urlencoded
                    do_urlencode = l.is_ascii_uppercase();

                    state = 2;

                    // read number as well here(if any)
                    match Self::read_number(data)? {
                        (number_offset, Some(number)) => {
                            offset += number_offset;
                            data = &data[number_offset..];
                            number_data = Some(number);
                        }
                        (offset, None) => {
                            debug_assert_eq!(offset, 0);
                        }
                    }
                }
                // found reverse modifier
                (2, 'r') => {
                    is_reverse = true;
                    state = 3;
                }
                // found delimiter chars(optional) no matter if reverse was found or not
                (2, l) | (3, l) if ['.', '-', '+', ',', '/', '_', '='].contains(&l) => {
                    delimiter.insert(l); // there may be many delimiter characters
                    state = 3;
                }
                (2, '}') | (3, '}') | (4, '}') => {
                    state = 0;
                    break;
                }
                (_, _) => {
                    return Err(MacroEvaluationError::ParsingSyntaxError);
                }
            }
        }

        if state != 0 {
            return Err(MacroEvaluationError::ParsingSyntaxError);
        }

        if let Some(letter) = letter {
            debug_assert!(letter.is_ascii_alphabetic());
            self.put_formatter(letter as u8, is_reverse, do_urlencode, number_data, delimiter)?;
        }

        self.input = &self.input[offset..];


        Ok(())
    }

    fn consume_token(&mut self) -> Result<(), MacroEvaluationError> {
        if self.input.len() == 0 {
            Ok(())
        } else {
            let c = self.input.chars().nth(0).unwrap();
            self.input = &self.input[c.len_utf8()..];
            if c == '%' {
                self.consume_after_percentage_token()?;
            } else {
                self.res.push(c);
            }
            Ok(())
        }
    }

    /// # Note
    /// inc case of error state is corrupted and this evaluator must not be used anymore
    fn consume_tokens(&mut self) -> Result<(), MacroEvaluationError> {
        loop {
            if self.input.len() == 0 {
                break;
            }
            self.consume_token()?;
        }
        Ok(())
    }
}

/// evaluate_macro evaluates given SPF macro with given evaluation context
///
/// # Docs
/// Take a look at [RFC7280](https://tools.ietf.org/html/rfc7208) section `7. Macros`
///
/// # Note
/// It DOES NOT check validity of created data. So for instance generated domains MAY NOT BE VALID!
pub fn evaluate_macro<E>(evaluation_context: E, macro_text: &str) -> Result<String, MacroEvaluationError>
    where E: EvaluationContext
{
    let mut e = MacroEvaluator {
        input: macro_text,
        res: String::with_capacity(macro_text.len()),
        ctx: evaluation_context,
    };
    e.consume_tokens()?;
    Ok(e.res)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use lazy_static::lazy_static;

    use super::*;

    lazy_static! {
        static ref DEFAULT_OPTIONS_MAP: HashMap<MacroVariable, &'static str> = {
            let mut m = HashMap::new();
            m.insert(MacroVariable::Sender, "sender");
            m.insert(MacroVariable::DomainNameOfHostPerformingTheCheck, "a.b.c.d");
            m.insert(MacroVariable::HeloOrEhloDomain, "  ");
            m.insert(MacroVariable::SmtpClientIp, "a.b-c=d");
            m
        };
    }

    #[test]
    fn test_can_evaluate_macro() {
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{r1}").unwrap(), "a");

        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{r10}").unwrap(), "a.b.c.d");

        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "asdf").unwrap(), "asdf");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%_").unwrap(), " ");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%%").unwrap(), "%");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%-").unwrap(), "%20");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%s").unwrap(), "sender");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{sr}").unwrap(), "sender");

        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{r}").unwrap(), "a.b.c.d");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{r0}").unwrap(), "");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{rr}").unwrap(), "d.c.b.a");

        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{H}").unwrap(), "++");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{Hr}").unwrap(), "++");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%H").unwrap(), "++");

        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{c.-=}").unwrap(), "a.b.c.d");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{cr.-=}").unwrap(), "d.c.b.a");
        assert_eq!(evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%{c0r.-=}").unwrap(), "");

        evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%").unwrap_err();
        evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%q").unwrap_err();
        evaluate_macro(&*DEFAULT_OPTIONS_MAP, "%t").unwrap_err();
    }
}