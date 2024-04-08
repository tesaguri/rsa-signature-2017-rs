use core::fmt::{self, Debug, Display, Formatter};
use core::marker::PhantomData;

use serde::de::{self, Unexpected, Visitor};
use serde::ser::{self, Impossible, Serialize};

use crate::Signature;

/// An `impl Serialize` wrapper for a map value that appends the given `Signature` to the map as the
/// `signature` enrry value when serializing.
///
/// It raises an error if the wrapped value does not serialize to a map.
pub struct InsertSignature<'a, T> {
    value: T,
    signature: &'a Signature<'a>,
}

/// A pseudo  `Serializer` that yields an `Ok` iff the "serialized" value equals to `"signature"`.
struct EqSignature;

/// A wrapper to reuse the ctors of `de::Error` to construct `ser::Error` (HACK).
struct SerErrorAsDeError<E>(E);

impl<'a, T: Serialize> InsertSignature<'a, T> {
    pub fn new(value: T, signature: &'a Signature<'a>) -> Self {
        Self { value, signature }
    }
}

impl<'a, T: Serialize> Serialize for InsertSignature<'a, T> {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        struct Serializer<'a, S> {
            inner: S,
            signature: &'a Signature<'a>,
        }

        return self.value.serialize(Serializer {
            inner: serializer,
            signature: self.signature,
        });

        struct SerializeMap<'a, S> {
            inner: S,
            signature: &'a Signature<'a>,
            skip_next_value: bool,
        }

        struct SerializeStruct<'a, S> {
            inner: S,
            signature: Option<&'a Signature<'a>>,
        }

        /// A pseudo `Visitor` for reusing its default impls as "factories" of `S::Error` (HACK).
        struct ErrorFactory<T> {
            marker: PhantomData<fn() -> T>,
        }

        impl<'a, S: ser::Serializer> ser::Serializer for Serializer<'a, S> {
            type Ok = S::Ok;
            type Error = S::Error;
            type SerializeMap = SerializeMap<'a, S::SerializeMap>;
            type SerializeStruct = SerializeStruct<'a, S::SerializeStruct>;
            type SerializeSeq = Impossible<Self::Ok, Self::Error>;
            type SerializeTuple = Impossible<Self::Ok, Self::Error>;
            type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;
            type SerializeTupleVariant = Impossible<Self::Ok, Self::Error>;
            type SerializeStructVariant = Impossible<Self::Ok, Self::Error>;

            fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
                self.inner
                    .serialize_map(len.map(|len| len + 1))
                    .map(|inner| SerializeMap {
                        inner,
                        signature: self.signature,
                        skip_next_value: false,
                    })
            }

            fn serialize_struct(
                self,
                name: &'static str,
                len: usize,
            ) -> Result<Self::SerializeStruct, Self::Error> {
                self.inner
                    .serialize_struct(name, len + 1)
                    .map(|inner| SerializeStruct {
                        inner,
                        signature: Some(self.signature),
                    })
            }

            fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_bool(v).map_err(into_ser_error)
            }

            fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
                self.serialize_i64(v.into())
            }

            fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
                self.serialize_i64(v.into())
            }

            fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
                self.serialize_i64(v.into())
            }

            fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_i64(v).map_err(into_ser_error)
            }

            fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_i128(v).map_err(into_ser_error)
            }

            fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
                self.serialize_u64(v.into())
            }

            fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
                self.serialize_u64(v.into())
            }

            fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
                self.serialize_u64(v.into())
            }

            fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_u64(v).map_err(into_ser_error)
            }

            fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_u128(v).map_err(into_ser_error)
            }

            fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
                self.serialize_f64(v.into())
            }

            fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_f64(v).map_err(into_ser_error)
            }

            fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_char(v).map_err(into_ser_error)
            }

            fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_str(v).map_err(into_ser_error)
            }

            fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_bytes(v).map_err(into_ser_error)
            }

            fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_none().map_err(into_ser_error)
            }

            fn serialize_some<T: ?Sized>(self, v: &T) -> Result<Self::Ok, Self::Error>
            where
                T: Serialize,
            {
                v.serialize(self)
            }

            fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
                ErrorFactory::new().visit_unit().map_err(into_ser_error)
            }

            fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::Other("unit struct"),
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_unit_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
            ) -> Result<Self::Ok, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::UnitVariant,
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_newtype_struct<T: ?Sized>(
                self,
                _: &'static str,
                _: &T,
            ) -> Result<Self::Ok, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::NewtypeStruct,
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_newtype_variant<T: ?Sized>(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: &T,
            ) -> Result<Self::Ok, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::NewtypeVariant,
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::Seq,
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::Other("tuple"),
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_tuple_struct(
                self,
                _: &'static str,
                _: usize,
            ) -> Result<Self::SerializeTupleStruct, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::Other("tuple struct"),
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_tuple_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: usize,
            ) -> Result<Self::SerializeTupleVariant, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::TupleVariant,
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn serialize_struct_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: usize,
            ) -> Result<Self::SerializeStructVariant, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::StructVariant,
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }

            fn collect_str<T: ?Sized>(self, _: &T) -> Result<Self::Ok, Self::Error> {
                Err(into_ser_error(de::Error::invalid_type(
                    Unexpected::Other("string"),
                    &ErrorFactory::<Self::Ok>::new(),
                )))
            }
        }

        impl<'a, S: ser::SerializeMap> ser::SerializeMap for SerializeMap<'a, S> {
            type Ok = S::Ok;
            type Error = S::Error;

            fn serialize_key<T: ?Sized>(&mut self, key: &T) -> Result<(), Self::Error>
            where
                T: Serialize,
            {
                if key.serialize(EqSignature).is_ok() {
                    self.skip_next_value = true;
                    Ok(())
                } else {
                    self.inner.serialize_key(key)
                }
            }

            fn serialize_value<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
            where
                T: Serialize,
            {
                if self.skip_next_value {
                    self.skip_next_value = false;
                    Ok(())
                } else {
                    self.inner.serialize_value(value)
                }
            }

            fn serialize_entry<K: ?Sized, V: ?Sized>(
                &mut self,
                key: &K,
                value: &V,
            ) -> Result<(), Self::Error>
            where
                K: Serialize,
                V: Serialize,
            {
                if key.serialize(EqSignature).is_ok() {
                    Ok(())
                } else {
                    self.inner.serialize_entry(key, value)
                }
            }

            fn end(mut self) -> Result<Self::Ok, Self::Error> {
                self.inner.serialize_entry("signature", self.signature)?;
                self.inner.end()
            }
        }

        impl<'a, S: ser::SerializeStruct> ser::SerializeStruct for SerializeStruct<'a, S> {
            type Ok = S::Ok;
            type Error = S::Error;

            fn serialize_field<T: ?Sized>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Self::Error>
            where
                T: Serialize,
            {
                match key {
                    "signature" => Ok(()),
                    _ => self.inner.serialize_field(key, value),
                }
            }

            fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
                match key {
                    "signature" => {
                        self.signature = None;
                        Ok(())
                    }
                    _ => self.inner.skip_field(key),
                }
            }

            fn end(mut self) -> Result<Self::Ok, Self::Error> {
                if let Some(signature) = self.signature {
                    self.inner.serialize_field("signature", signature)?;
                }
                self.inner.end()
            }
        }

        impl<T> ErrorFactory<T> {
            fn new() -> Self {
                Self {
                    marker: PhantomData,
                }
            }
        }

        impl<'de, T> Visitor<'de> for ErrorFactory<T> {
            type Value = T;

            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str("a map")
            }
        }
    }
}

impl ser::Serializer for EqSignature {
    type Ok = ();
    // Using `fmt::Error` that happens to be a size-efficient type which implements `ser::Error`.
    type Error = fmt::Error;
    type SerializeSeq = Impossible<Self::Ok, Self::Error>;
    type SerializeTuple = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = Impossible<Self::Ok, Self::Error>;
    type SerializeMap = Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeStructVariant = Impossible<Self::Ok, Self::Error>;

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        match v {
            "signature" => Ok(()),
            _ => Err(fmt::Error),
        }
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        match v {
            b"signature" => Ok(()),
            _ => Err(fmt::Error),
        }
    }

    fn collect_str<T: ?Sized>(self, v: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Display,
    {
        if fmt_cmp::eq(v, "signature") {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }

    fn serialize_bool(self, _: bool) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_i8(self, _: i8) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_i16(self, _: i16) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_i32(self, _: i32) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_i64(self, _: i64) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_i128(self, _: i128) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_u8(self, _: u8) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_u16(self, _: u16) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_u32(self, _: u32) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_u64(self, _: u64) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_u128(self, _: u128) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_f32(self, _: f32) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_f64(self, _: f64) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_char(self, _: char) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_some<T: ?Sized>(self, v: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        v.serialize(EqSignature)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(fmt::Error)
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(fmt::Error)
    }
}

impl<E: ser::Error> de::Error for SerErrorAsDeError<E> {
    fn custom<T: Display>(msg: T) -> Self {
        Self(E::custom(msg))
    }
}

impl<E: ser::StdError> ser::StdError for SerErrorAsDeError<E> {}

impl<E: Debug> Debug for SerErrorAsDeError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<E: Display> Display for SerErrorAsDeError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn into_ser_error<E>(SerErrorAsDeError(e): SerErrorAsDeError<E>) -> E {
    e
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;

    use serde::Serialize;
    use serde_test::{assert_ser_tokens, assert_ser_tokens_error, Token};
    use sophia_iri::Iri;

    use crate::{Signature, SignatureType};

    use super::*;

    const SIGNATURE: Signature<'_> = Signature {
        _context: (),
        kind: SignatureType::RsaSignature2017,
        created: Cow::Borrowed("1990-01-01T00:00:00Z"),
        creator: Iri::new_unchecked_const("https://example.com/#me"),
        domain: None,
        nonce: Some(Cow::Borrowed("deadbeef12345678")),
        signature_value: Vec::new(),
    };
    const SIGNATURE_REF: &Signature<'_> = &SIGNATURE;
    const SIGNATURE_TOKENS: &[Token] = &[
        Token::Struct {
            name: "Signature",
            len: 6,
        },
        Token::Str("@context"),
        Token::Seq { len: Some(2) },
        Token::Str("https://w3id.org/security/v1"),
        Token::Struct {
            name: "InlineContext",
            len: 1,
        },
        Token::Str("@vocab"),
        Token::Str("sec:"),
        Token::StructEnd,
        Token::SeqEnd,
        Token::Str("type"),
        Token::UnitVariant {
            name: "SignatureType",
            variant: "RsaSignature2017",
        },
        Token::Str("created"),
        Token::Str("1990-01-01T00:00:00Z"),
        Token::Str("creator"),
        Token::Str("https://example.com/#me"),
        Token::Str("nonce"),
        Token::Some,
        Token::Str("deadbeef12345678"),
        Token::Str("signatureValue"),
        Token::Str(""),
        Token::StructEnd,
    ];

    #[test]
    fn inserts_new_struct_field() {
        #[derive(Serialize)]
        struct Test {
            a: u32,
        }

        let value = Test { a: 42 };
        let wrapper = InsertSignature::new(&value, &SIGNATURE_REF);

        let mut tokens = vec![
            Token::Struct {
                name: "Test",
                len: 2,
            },
            Token::Str("a"),
            Token::U32(42),
            Token::Str("signature"),
        ];
        tokens.extend(SIGNATURE_TOKENS);
        tokens.push(Token::StructEnd);
        assert_ser_tokens(&wrapper, &tokens);
    }

    #[test]
    fn inserts_new_map_entry() {
        let value = HashMap::<_, _>::from_iter([("a", 42u32)]);
        let wrapper = InsertSignature::new(&value, &SIGNATURE_REF);

        let mut tokens = vec![
            Token::Map { len: Some(2) },
            Token::Str("a"),
            Token::U32(42),
            Token::Str("signature"),
        ];
        tokens.extend(SIGNATURE_TOKENS);
        tokens.push(Token::MapEnd);
        assert_ser_tokens(&wrapper, &tokens);
    }

    #[test]
    fn replaces_existing_struct_field() {
        #[derive(Serialize)]
        struct Test {
            signature: Signature<'static>,
        }

        let value = Test {
            signature: Signature {
                nonce: Some("12345678deadbeef".into()),
                ..SIGNATURE
            },
        };
        let wrapper = InsertSignature::new(&value, &SIGNATURE_REF);

        let mut tokens = vec![
            Token::Struct {
                name: "Test",
                len: 2, // FIXME: This should be `1`
            },
            Token::Str("signature"),
        ];
        tokens.extend(SIGNATURE_TOKENS);
        tokens.push(Token::StructEnd);
        assert_ser_tokens(&wrapper, &tokens);
    }

    #[test]
    fn replaces_existing_map_entry() {
        let value = HashMap::<_, _>::from_iter([(
            "signature",
            Signature {
                nonce: Some("12345678deadbeef".into()),
                ..SIGNATURE
            },
        )]);
        let wrapper = InsertSignature::new(&value, &SIGNATURE_REF);

        let mut tokens = vec![
            Token::Map {
                len: Some(2), // FIXME: This should be `1`
            },
            Token::Str("signature"),
        ];
        tokens.extend(SIGNATURE_TOKENS);
        tokens.push(Token::MapEnd);
        assert_ser_tokens(&wrapper, &tokens);
    }

    #[test]
    fn errors_if_type_mismatch() {
        let value = 42u32;
        let wrapper = InsertSignature::new(value, &SIGNATURE_REF);
        assert_ser_tokens_error(&wrapper, &[], "invalid type: integer `42`, expected a map");

        let value = [42];
        let wrapper = InsertSignature::new(value, &SIGNATURE_REF);
        assert_ser_tokens_error(&wrapper, &[], "invalid type: tuple, expected a map");
    }
}
