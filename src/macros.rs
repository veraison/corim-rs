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
/// use serde::{Serialize, Deserialize};
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
    ($(($tag_num:expr, $title:ident, $type:ty $(, $($lt:lifetime),* )?, $doc_comments:literal)),* $(,)?) => {
        $(
            #[doc = $doc_comments]
            #[derive(Debug, ::serde::Serialize, ::serde::Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
            #[repr(C)]
            pub struct $title $(< $($lt),* >)? (::ciborium::tag::Accepted<$type, $tag_num>);

            impl $(< $($lt),* >)? $title $(< $($lt),* >)? {
                /// Creates a new wrapped instance from the provided value
                #[inline]
                pub const fn new(value: $type) -> Self {
                    Self (::ciborium::tag::Accepted(value))
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
        )*
    };
}
