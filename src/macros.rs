// SPDX-License-Identifier: MIT

/// Generates a wrapper struct and implementations for CBOR-tagged types.
///
/// This macro creates a new struct that wraps a value with a CBOR tag number, along with
/// common trait implementations for accessing and converting the wrapped value.
///
/// # Parameters
///
/// The macro accepts a comma-separated list of tuples with the following elements:
///
/// * `tag_num`: The CBOR tag number as a literal expression
/// * `title`: The identifier for the generated wrapper struct
/// * `type`: The type being wrapped
/// * `doc_comments`: Documentation string for the generated struct
///
/// # Generated Items
///
/// For each tuple, the macro generates:
///
/// * A struct named `title` containing the wrapped value
/// * Implementation of `new()` constructor
/// * Common trait implementations:
///   - `AsRef<T>`
///   - `AsMut<T>`
///   - `Deref<Target = T>`
///   - `DerefMut`
///   - `From<T>`
///   - `Serialize`
///   - `Deserialize`
///
/// # Example
///
/// ```
/// use serde::{
///     ser::SerializeMap,
///     Serialize, Deserialize,
/// };
/// use ciborium::tag::Accepted;
///
/// // This macro is exported from the crate
/// use corim_rs::generate_tagged;
///
/// // Define a simple type to wrap
/// #[derive(Default, Debug, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord, Clone)]
/// pub struct MyType(u32);
///
/// // Generate the tagged wrapper
/// generate_tagged!((
///     42,  // CBOR tag number
///     TaggedMyType,  // Generated struct name
///     MyType,  // Type to wrap
///     "my-type",
///     "A wrapped MyType with CBOR tag 42"  // Documentation
/// ));
///
/// // Create and use the wrapper
/// let value = MyType(123);
/// let tagged = TaggedMyType::new(value);
///
/// // Access via Deref
/// assert_eq!(tagged.0.0.0, 123);
///
/// // Convert using From
/// let tagged2: TaggedMyType = MyType(456).into();
///
/// // Access via AsRef
/// assert_eq!(tagged2.as_ref().0, 456);
/// ```
///
/// # Notes
///
/// * The wrapped value is stored in a `ciborium::tag::Accepted<T, N>` field
/// * The generated struct is marked with `#[repr(C)]` for consistent layout
/// * All implementations are derived using the standard library traits
///
#[macro_export]
macro_rules! generate_tagged {
    // Combined pattern that handles both with and without lifetime parameters
    ($(($tag_num:expr, $title:ident, $type:ty $(, $($lt:lifetime),* )?, $name:literal, $doc_comments:literal)),* $(,)?) => {
        $(
            #[doc = $doc_comments]
            #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
            #[repr(C)]
            pub struct $title $(< $($lt),* >)? (pub ::ciborium::tag::Accepted<$type, $tag_num>);

            impl $(< $($lt),* >)? $title $(< $($lt),* >)? {
                /// Creates a new wrapped instance from the provided value
                #[inline]
                pub const fn new(value: $type) -> Self {
                    Self (::ciborium::tag::Accepted(value))
                }

                /// Unwrap the tag, returing the inner value
                #[inline]
                pub fn unwrap(self) -> $type {
                    self.0.0
                }
            }

            impl $(< $($lt),* >)? std::convert::AsRef<$type> for $title $(< $($lt),* >)? {
                fn as_ref(&self) -> &$type {
                    &self.0.0
                }
            }

            impl $(< $($lt),* >)? std::convert::AsMut<$type> for $title $(< $($lt),* >)? {
                fn as_mut(&mut self) -> &mut $type {
                    &mut self.0.0
                }
            }

            impl $(< $($lt),* >)? std::ops::Deref for $title $(< $($lt),* >)? {
                type Target = $type;

                fn deref(&self) -> &Self::Target {
                    &self.0.0
                }
            }

            impl $(< $($lt),* >)? std::ops::DerefMut for $title $(< $($lt),* >)? {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0.0
                }
            }

            impl $(< $($lt),* >)? std::convert::From<$type> for $title $(< $($lt),* >)? {
                fn from(value: $type) -> Self {
                    Self::new(value)
                }
            }

            impl $(< $($lt),* >)? ::serde::ser::Serialize for $title $(< $($lt),* >)? {
                fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    if serializer.is_human_readable() {
                        let mut state = serializer.serialize_map(Some(2))?;
                        state.serialize_entry("type", $name)?;
                        state.serialize_entry("value", &self.0.0)?;
                        state.end()
                    } else {
                        self.0.serialize(serializer)
                    }
                }
            }

            impl < $( $($lt),* ,)? 'de> ::serde::de::Deserialize<'de> for $title $(< $($lt),* >)? {
                fn deserialize<D>(deserializer: D) -> ::core::result::Result<$title $(< $($lt),* >)?  , D::Error>
                where
                    D: ::serde::de::Deserializer<'de>,
                {
                    struct __Visitor <'de, $( $($lt),* )?> {
                        marker: std::marker::PhantomData< $title $(< $($lt),* >)? >,
                        lifetime: std::marker::PhantomData<&'de () >,
                    }

                    impl<'de, $( $($lt),* ,)? > ::serde::de::Visitor<'de> for __Visitor<'de, $( $($lt),* )?> {
                        type Value = $title $(< $($lt),* >)?;

                        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                            formatter.write_str(
                                &format!("{} struct", stringify!(title)),
                                )
                        }

                        fn visit_map<A>(self, mut map: A) -> ::core::result::Result<Self::Value, A::Error>
                        where
                            A: ::serde::de::MapAccess<'de>
                        {
                            let mut ret = Err(::serde::de::Error::custom(format!("no \"value\" entry in map")));
                            let mut seen_tag: bool = false;
                            loop {
                                match map.next_key::<&str>()? {
                                    Some("type") => {
                                        let typ: String = map.next_value()?;
                                        if typ != $name {
                                            return Err(::serde::de::Error::custom(format!(
                                                        "expected type {}, found {}",
                                                        $name,
                                                        typ,
                                                    )));
                                        }

                                        seen_tag = true;
                                    },
                                    Some("value") => {
                                        ret = Ok($title::new(map.next_value::<$type>()?));
                                    },
                                    Some(s) => {
                                        return Err(::serde::de::Error::custom(
                                                format!("unexpected map entry: {}", s)
                                                ));
                                    },
                                    None => break,
                                }
                            }

                            if seen_tag {
                                ret
                            } else {
                                Err(::serde::de::Error::custom("no \"tag\" entry in map"))
                            }
                        }
                    }

                    if deserializer.is_human_readable() {
                        deserializer.deserialize_map(__Visitor
                            {
                                marker: std::marker::PhantomData,
                                lifetime: std::marker::PhantomData,
                            })
                    } else {
                        Ok($title(::ciborium::tag::Accepted::deserialize(deserializer)?))
                    }
                }
            }

        )*
    };
}

#[cfg_attr(test, macro_export)]
macro_rules! _compare {
    ($expected:expr, $actual:expr) => {
        print!("Expected: ");
        for byte in $expected {
            print!("0x{:02X?}, ", byte);
        }
        println!();
        print!("Actual: ");
        for byte in $actual {
            print!("0x{:02X?}, ", byte);
        }
        println!();
    };
}

/// Calcuclate the  "map length" of a struct to be used for CBOR encoding.
/// The first argument is the struct, followed by the fixed part of the
/// length (number of mandotory fields and extensions), followed by a list
/// of optional fields that need to be evaluated.
///
///  For example, for [CorimSignerMap] that has one mandatory field,
///  extensions, and, one optional signer_uri, field, this would be:
///
/// ```ignore
///  let len = map_len!(
///     self,
///     1+self.extensions.as_ref().map_or(0, |e| e.len()),
///     signer_uri,
///  );
/// ```
macro_rules! map_len {
    ($s:expr, $mandatory_count:expr, $($opt_field:ident),* $(,)?) => {
        $mandatory_count $(+ ($s.$opt_field.is_some() as usize))*
    };
}
