// SPDX-License-Identifier: MIT

use std::{
    cmp::Ordering, fmt::{Debug, Display}, hash::Hash, ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref,
        DerefMut, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    }, str::FromStr
};

use serde::Serialize;

use crate::error::NumbersError;

macro_rules! all_integers {
    ($callback:ident) => {
        $callback!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);
    };
}

/// Provides restrictions to which underlying integer types may be stored as
/// the [`Inner`] type of [`EncodedInteger`].
mod private {
    /// A sealed trait that prevents external implementations of the `IntegerType` trait.
    /// 
    /// This trait is part of the sealed traits pattern, ensuring that only types
    /// within this crate can implement the public `IntegerType` trait.
    pub trait Sealed {}

    macro_rules! sealed_types {
        ($($t:ty),+) => {
            $(
                impl Sealed for $t {}
            )+
        }
    }

    all_integers!(sealed_types);
}

/// Defines the common interface for integer types used within this crate.
///
/// This trait is sealed and can only be implemented for the predefined integer types
/// within this crate. It provides methods for converting between different integer
/// representations and for querying the bounds of each type.
///
/// # Type Parameters
/// The implementing type must be:
/// * `Sized` - Have a known size at compile time
/// * `PartialOrd` - Support partial ordering operations
/// * `Copy` - Support copy semantics
/// * `Debug` - Support debug formatting
/// * `private::Sealed` - Part of the sealed trait pattern
pub trait IntegerType: Sized + PartialOrd + Copy + Debug + private::Sealed {
    /// Converts the implementing integer type to an i128 representation.
    ///
    /// # Returns
    /// The value as an i128 integer.
    fn as_i128(&self) -> i128;

    /// Returns the maximum value representable by this integer type.
    ///
    /// # Returns
    /// The maximum value of this integer type.
    fn max_value() -> Self;

    /// Returns the minimum value representable by this integer type.
    ///
    /// # Returns
    /// The minimum value of this integer type.
    fn min_value() -> Self;
}

macro_rules! impl_integer_type {
    ($($t:ty),+ $(,)*) => {
        $(
            impl IntegerType for $t {
                fn as_i128(&self) -> i128 {
                    *self as i128
                }

                fn max_value() -> Self {
                    <$t>::MAX
                }

                fn min_value() -> Self {
                    <$t>::MIN
                }
            }
        )+
    }
}

all_integers!(impl_integer_type);

/// Defines a common interface for types that wrap integer values.
///
/// This trait provides methods for accessing the wrapped integer and determining
/// how it should be serialized according to CBOR encoding rules. Types implementing
/// this trait can be used in contexts where CBOR-compatible integer representation is required.
pub trait WrappedInteger {
    /// The underlying integer type that is wrapped.
    type Inner: IntegerType;

    /// Returns a reference to the inner integer value.
    ///
    /// # Returns
    /// The inner integer value of type `Self::Inner`.
    fn inner(&self) -> Self::Inner;

    /// Calculates the length in bytes of the serialized CBOR representation.
    ///
    /// The length depends on the magnitude of the integer and follows CBOR encoding rules:
    /// - Values in range -24 to 23: 1 byte
    /// - 8-bit values: 2 bytes
    /// - 16-bit values: 3 bytes
    /// - 32-bit values: 5 bytes
    /// - 64-bit values: 9 bytes
    /// - 128-bit values: 17 bytes
    ///
    /// # Returns
    /// The number of bytes needed for the CBOR representation.
    fn serialized_len(&self) -> usize {
        let number: i128 = self.inner().as_i128();

        // Small 8-bit values.
        if (-24..24).contains(&number) {
            return 1;
        }

        // Find the base_2 logarithm of the absolute value of the number
        // to see which type it would fit into.
        match number.abs().ilog2() {
            0..=7 => 2,                          // 8-bit values larger than 23
            8..=15 => 3,                         // 16-bit values
            16..=31 => 5,                        // 32-bit values
            32..=63 => 9,                        // 64-bit values
            _ => number.to_ne_bytes().len() + 1, // 128-bit values
        }
    }

    /// Compares two integers based on their CBOR serialized form.
    ///
    /// This follows CBOR's canonical ordering rules:
    /// 1. Shorter representations are less than longer ones
    /// 2. With equal length, positive numbers are less than negative ones
    /// 3. With equal length and sign, compare the actual values
    ///
    /// # Parameters
    /// * `other` - Another `WrappedInteger` to compare against
    ///
    /// # Returns
    /// The ordering relation between the two values in CBOR canonical form.
    fn serialized_cmp(&self, other: &Self) -> Ordering {
        // First compare by length of serialized representation
        match self.serialized_len().cmp(&other.serialized_len()) {
            Ordering::Equal => {
                // When lengths equal, negative numbers are higher than positive
                let (lhs, rhs): (i128, i128) = (self.inner().as_i128(), other.inner().as_i128());
                match (lhs.is_negative(), rhs.is_negative()) {
                    (false, true) => Ordering::Less,
                    (true, false) => Ordering::Greater,
                    // When signs match, compare values (with reversed ordering for negatives)
                    _ => {
                        if lhs.is_negative() {
                            rhs.cmp(&lhs)
                        } else {
                            lhs.cmp(&rhs)
                        }
                    }
                }
            }
            ordering => ordering,
        }
    }
}

/// A generic representation of an integer value which will
/// properly encode to CBOR based upon the underlying value stored
/// in the wrapped field.
///
/// Note that serialized `Integer` values maintain consistent representation
/// across architectures, but deserialization to platform-specific types
/// (like `usize`/`isize`) should be validated when handling data
/// that might cross architecture boundaries.
#[derive(Default, PartialEq, Eq, Clone, Copy, Ord, PartialOrd)]
pub struct Integer(pub i128);


impl Integer {
    // Add these constants to the impl block
    /// Constant representing zero
    pub const ZERO: Self = Integer(0);
    
    /// Constant representing one
    pub const ONE: Self = Integer(1);

    /// Constant representing the minimum value
    pub const MIN: Self = Integer(i128::MIN);
    
    /// Constant representing the maximum value
    pub const MAX: Self = Integer(i128::MAX);

    /// Creates a new `Integer` from the given value.
    pub fn new<T: IntegerType>(value: T) -> Self {
        Integer(value.as_i128())
    }

    /// Checks if this integer is zero.
    ///
    /// # Returns
    /// `true` if the integer is zero, otherwise `false`.
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Returns the absolute value of the integer.
    ///
    /// # Returns
    /// A new `Integer` containing the absolute value.
    pub const fn abs(&self) -> Self {
        if self.0 < 0 {
            Integer(-self.0)
        } else {
            *self
        }
    }

    /// Returns the absolute difference between this integer and another.
    ///
    /// Calculates the absolute value of the difference between two integers.
    ///
    /// # Parameters
    /// * `other` - The integer to find the difference with
    ///
    /// # Returns
    /// A new `Integer` containing the absolute difference.
    pub const fn abs_diff(&self, other: &Self) -> Self {
        let diff = self.0 - other.0;
        if diff < 0 {
            Integer(-diff)
        } else {
            Integer(diff)
        }
    }

    /// Returns the absolute value of the integer, checking for overflow.
    ///
    /// This function returns `None` if the absolute value of the integer
    /// would overflow (which can only happen for the minimum value of i128).
    ///
    /// # Returns
    /// * `Some(Integer)` - The absolute value if it can be represented
    /// * `None` - If the absolute value would overflow
    pub const fn checked_abs(&self) -> Option<Self> {
        if self.0 < 0 {
            match self.0.checked_neg() {
                Some(result) => Some(Integer(result)),
                None => None,
            }
        } else {
            Some(*self)
        }
    }

    /// Performs checked integer addition.
    ///
    /// Returns `None` if the operation would overflow.
    ///
    /// # Parameters
    /// * `other` - The value to add to this integer
    ///
    /// # Returns
    /// * `Some(Integer)` - The sum if it can be represented
    /// * `None` - If the addition would overflow
    pub const fn checked_add(&self, other: &Self) -> Option<Self> {
        if i128::MAX - self.0 >= other.0 && i128::MIN - self.0 <= other.0 {
            match self.0.checked_add(other.0) {
                Some(result) => Some(Integer(result)),
                None => None,
            }
        } else {
            None
        }
    }

    /// Performs checked integer addition with an unsigned value.
    ///
    /// Returns `None` if the operation would overflow.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to add to this integer
    ///
    /// # Returns
    /// * `Some(i128)` - The sum if it can be represented
    /// * `None` - If the addition would overflow
    pub const fn checked_add_unsigned(&self, rhs: u128) -> Option<i128> {
        if i128::MAX - self.0 >= rhs as i128 && i128::MIN - self.0 <= rhs as i128 {
            self.0.checked_add(rhs as i128)
        } else {
            None
        }
    }

    /// Performs checked integer division.
    ///
    /// Returns `None` if the operation would result in division by zero.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// * `Some(Integer)` - The quotient if it can be represented
    /// * `None` - If the division would result in division by zero
    pub const fn checked_div(&self, other: &Self) -> Option<Self> {
        if other.0 == 0 {
            return None;
        }
        match self.0.checked_div(other.0) {
            Some(result) => Some(Integer(result)),
            None => None,
        }
    }

    /// Performs checked Euclidean division.
    ///
    /// Returns `None` if the operation would result in division by zero.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// * `Some(Integer)` - The quotient if it can be represented
    /// * `None` - If the division would result in division by zero
    pub const fn checked_div_euclid(&self, other: &Self) -> Option<Self> {
        if other.0 == 0 {
            return None;
        }
        match self.0.checked_div_euclid(other.0) {
            Some(result) => Some(Integer(result)),
            None => None,
        }
    }

    /// Computes the integer base logarithm.
    ///
    /// Returns `None` if the base is less than or equal to 1 or if the integer is less than or equal to 0.
    ///
    /// # Parameters
    /// * `base` - The base of the logarithm
    ///
    /// # Returns
    /// * `Some(u32)` - The logarithm if it can be computed
    /// * `None` - If the base or integer is invalid
    pub const fn check_ilog(&self, base: i128) -> Option<u32> {
        if self.0 <= 0 || base <= 1 {
            return None;
        }
        Some(self.0.ilog(base))
    }

    /// Computes the base-2 logarithm.
    ///
    /// Returns `None` if the integer is less than or equal to 0.
    ///
    /// # Returns
    /// * `Some(u32)` - The logarithm if it can be computed
    /// * `None` - If the integer is invalid
    pub const fn checked_ilog2(&self) -> Option<u32> {
        if self.0 <= 0 {
            return None;
        }
        Some(self.0.ilog2())
    }

    /// Computes the base-10 logarithm.
    ///
    /// Returns `None` if the integer is less than or equal to 0.
    ///
    /// # Returns
    /// * `Some(u32)` - The logarithm if it can be computed
    /// * `None` - If the integer is invalid
    pub const fn checked_ilog10(&self) -> Option<u32> {
        if self.0 <= 0 {
            return None;
        }
        Some(self.0.ilog10())
    }

    /// Computes the integer square root.
    ///
    /// Returns `None` if the integer is negative.
    ///
    /// # Returns
    /// * `Some(Integer)` - The square root if it can be computed
    /// * `None` - If the integer is invalid
    pub const fn checked_isqrt(&self) -> Option<Self> {
        if self.0 < 0 {
            return None;
        }
        match self.0.checked_isqrt() {
            Some(result) => Some(Integer(result)),
            None => None,
        }
    }

    /// Performs checked integer multiplication.
    ///
    /// Returns `None` if the operation would overflow.
    ///
    /// # Parameters
    /// * `other` - The value to multiply this integer by
    ///
    /// # Returns
    /// * `Some(Integer)` - The product if it can be represented
    /// * `None` - If the multiplication would overflow
    pub const fn checked_mul(&self, other: &Self) -> Option<Self> {
        if i128::MAX / self.0 >= other.0 && i128::MIN / self.0 <= other.0 {
            match self.0.checked_mul(other.0) {
                Some(result) => Some(Integer(result)),
                None => None,
            }
        } else {
            None
        }
    }

    /// Performs checked integer negation.
    ///
    /// Returns `None` if the operation would overflow.
    ///
    /// # Returns
    /// * `Some(Integer)` - The negated value if it can be represented
    /// * `None` - If the negation would overflow
    pub const fn checked_neg(&self) -> Option<Self> {
        match self.0.checked_neg() {
            Some(result) => Some(Integer(result)),
            None => None,
        }
    }

    /// Performs checked integer exponentiation.
    ///
    /// Returns `None` if the operation would overflow.
    ///
    /// # Parameters
    /// * `exp` - The exponent
    ///
    /// # Returns
    /// * `Some(Integer)` - The result if it can be represented
    /// * `None` - If the exponentiation would overflow
    pub const fn checked_pow(&self, exp: u32) -> Option<Self> {
        match self.0.checked_pow(exp) {
            Some(result) => Some(Integer(result)),
            None => None,
        }
    }

    /// Performs checked integer remainder.
    ///
    /// Returns `None` if the operation would result in division by zero.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// * `Some(Integer)` - The remainder if it can be represented
    /// * `None` - If the division would result in division by zero
    pub const fn checked_rem(&self, other: &Self) -> Option<Self> {
        if other.0 == 0 {
            return None;
        }
        match self.0.checked_rem(other.0) {
            Some(result) => Some(Integer(result)),
            None => None,
        }
    }

    /// Performs checked Euclidean remainder.
    ///
    /// Returns `None` if the operation would result in division by zero.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// * `Some(Integer)` - The remainder if it can be represented
    /// * `None` - If the division would result in division by zero
    pub const fn checked_rem_euclid(&self, other: &Self) -> Option<Self> {
        if other.0 == 0 {
            return None;
        }
        match self.0.checked_rem_euclid(other.0) {
            Some(result) => Some(Integer(result)),
            None => None,
        }
    }

    /// Performs checked integer subtraction.
    ///
    /// Returns `None` if the operation would overflow.
    ///
    /// # Parameters
    /// * `other` - The value to subtract from this integer
    ///
    /// # Returns
    /// * `Some(Integer)` - The difference if it can be represented
    /// * `None` - If the subtraction would overflow
    pub const fn checked_sub(&self, other: &Self) -> Option<Self> {
        if i128::MAX - self.0 >= other.0 && i128::MIN - self.0 <= other.0 {
            match self.0.checked_sub(other.0) {
                Some(result) => Some(Integer(result)),
                None => None,
            }
        } else {
            None
        }
    }

    /// Performs checked integer subtraction with an unsigned value.
    ///
    /// Returns `None` if the operation would overflow.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to subtract from this integer
    ///
    /// # Returns
    /// * `Some(Integer)` - The difference if it can be represented
    /// * `None` - If the subtraction would overflow
    pub const fn checked_sub_unsigned(&self, rhs: u128) -> Option<Self> {
        if i128::MAX - self.0 >= rhs as i128 && i128::MIN - self.0 <= rhs as i128 {
            match self.0.checked_sub(rhs as i128) {
                Some(result) => Some(Integer(result)),
                None => None,
            }
        } else {
            None
        }
    }

    /// Counts the number of 1 bits in the binary representation of the integer.
    ///
    /// # Returns
    /// The number of 1 bits.
    pub const fn count_ones(&self) -> u32 {
        self.0.count_ones()
    }

    /// Counts the number of 0 bits in the binary representation of the integer.
    ///
    /// # Returns
    /// The number of 0 bits.
    pub const fn count_zeros(&self) -> u32 {
        self.0.count_zeros()
    }

    /// Performs integer division and rounds up to the nearest integer.
    ///
    /// # Returns
    /// A new `Integer` containing the result.
    pub const fn div_ceil(&self) -> Self {
        if self.0 < 0 {
            Integer(self.0 / -1)
        } else {
            Integer((self.0 + 1) / 2)
        }
    }

    /// Performs Euclidean division.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A new `Integer` containing the quotient.
    pub const fn div_euclid(&self, other: &Self) -> Self {
        if other.0 == 0 {
            panic!("Division by zero");
        }
        Integer(self.0.div_euclid(other.0))
    }

    /// Performs integer division and rounds down to the nearest integer.
    ///
    /// # Returns
    /// A new `Integer` containing the result.
    pub const fn div_floor(&self) -> Self {
        if self.0 < 0 {
            Integer(self.0 / -1)
        } else {
            Integer(self.0 / 2)
        }
    }

    /// Converts the integer to an ASCII character if it is within the ASCII range.
    ///
    /// # Returns
    /// * `Some(u8)` - The ASCII character if it can be represented
    /// * `None` - If the integer is outside the ASCII range
    pub const fn from_ascii(&self) -> Option<u8> {
        if self.0 >= 0 && self.0 <= 127 {
            Some(self.0 as u8)
        } else {
            None
        }
    }

    /// Converts the integer to an ASCII character using a specific radix.
    ///
    /// # Parameters
    /// * `radix` - The radix to use for conversion
    ///
    /// # Returns
    /// * `Some(u8)` - The ASCII character if it can be represented
    /// * `None` - If the integer is outside the range for the given radix
    pub const fn from_ascii_radix(&self, radix: u32) -> Option<u8> {
        if self.0 >= 0 && self.0 < radix as i128 {
            Some(self.0 as u8)
        } else {
            None
        }
    }

    /// Converts the integer from big-endian representation.
    ///
    /// # Returns
    /// A new `Integer` containing the converted value.
    pub const fn from_be(self) -> Self {
        if cfg!(target_endian = "big") {
            self
        } else {
            self.swap_bytes()
        }
    }

    /// Converts a byte array to an integer using big-endian representation.
    ///
    /// # Parameters
    /// * `bytes` - The byte array to convert
    ///
    /// # Returns
    /// A new `Integer` containing the converted value.
    pub const fn from_be_bytes(bytes: [u8; 16]) -> Self {
        if cfg!(target_endian = "big") {
            Integer(i128::from_be_bytes(bytes))
        } else {
            Integer(i128::from_le_bytes(bytes))
        }
    }

    /// Converts the integer from little-endian representation.
    ///
    /// # Returns
    /// A new `Integer` containing the converted value.
    pub const fn from_le(self) -> Self {
        if cfg!(target_endian = "little") {
            self
        } else {
            self.swap_bytes()
        }
    }

    /// Converts a byte array to an integer using little-endian representation.
    ///
    /// # Parameters
    /// * `bytes` - The byte array to convert
    ///
    /// # Returns
    /// A new `Integer` containing the converted value.
    pub const fn from_le_bytes(bytes: [u8; 16]) -> Self {
        if cfg!(target_endian = "little") {
            Integer(i128::from_le_bytes(bytes))
        } else {
            Integer(i128::from_be_bytes(bytes))
        }
    }

    /// Converts a byte array to an integer using native-endian representation.
    ///
    /// # Parameters
    /// * `bytes` - The byte array to convert
    ///
    /// # Returns
    /// A new `Integer` containing the converted value.
    pub const fn from_ne_bytes(bytes: [u8; 16]) -> Self {
        Integer(i128::from_ne_bytes(bytes))
    }

    /// Converts the integer to a string using a specific radix.
    ///
    /// # Parameters
    /// * `radix` - The radix to use for conversion
    ///
    /// # Returns
    /// * `Some(Integer)` - The converted value if it can be represented
    /// * `None` - If the integer is outside the range for the given radix
    pub const fn from_str_radix(&self, radix: u32) -> Option<Self> {
        if self.0 >= 0 && self.0 < radix as i128 {
            Some(Integer(self.0))
        } else {
            None
        }
    }

    /// Computes the integer base logarithm.
    ///
    /// # Parameters
    /// * `base` - The base of the logarithm
    ///
    /// # Returns
    /// The logarithm.
    pub const fn ilog(&self, base: i128) -> u32 {
        if self.0 <= 0 || base <= 1 {
            return 0;
        }
        self.0.ilog(base)
    }

    /// Computes the base-2 logarithm.
    ///
    /// # Returns
    /// The logarithm.
    pub const fn ilog2(&self) -> u32 {
        if self.0 <= 0 {
            return 0;
        }
        self.0.ilog2()
    }

    /// Computes the base-10 logarithm.
    ///
    /// # Returns
    /// The logarithm.
    pub const fn ilog10(&self) -> u32 {
        if self.0 <= 0 {
            return 0;
        }
        self.0.ilog10()
    }

    /// Checks if the integer is negative.
    ///
    /// # Returns
    /// `true` if the integer is negative, otherwise `false`.
    pub const fn is_negative(&self) -> bool {
        self.0 < 0
    }

    /// Checks if the integer is positive.
    ///
    /// # Returns
    /// `true` if the integer is positive, otherwise `false`.
    pub const fn is_positive(&self) -> bool {
        self.0 > 0
    }

    /// Computes the integer square root.
    ///
    /// # Returns
    /// A new `Integer` containing the square root.
    pub const fn isqrt(&self) -> Self {
        if self.0 < 0 {
            panic!("Square root of negative number");
        }
        Integer(self.0.isqrt())
    }

    /// Counts the number of leading 1 bits in the binary representation of the integer.
    ///
    /// # Returns
    /// The number of leading 1 bits.
    pub const fn leading_ones(&self) -> u32 {
        self.0.leading_ones()
    }

    /// Counts the number of leading 0 bits in the binary representation of the integer.
    ///
    /// # Returns
    /// The number of leading 0 bits.
    pub const fn leading_zeros(&self) -> u32 {
        self.0.leading_zeros()
    }

    /// Counts the number of trailing 0 bits in the binary representation of the integer.
    ///
    /// # Returns
    /// The number of trailing 0 bits.
    pub const fn trailing_zeros(&self) -> u32 {
        self.0.trailing_zeros()
    }

    /// Counts the number of trailing 1 bits in the binary representation of the integer.
    ///
    /// # Returns
    /// The number of trailing 1 bits.
    pub const fn trailing_ones(&self) -> u32 {
        self.0.trailing_ones()
    }

    /// Performs a left rotation of the bits in the integer.
    ///
    /// # Parameters
    /// * `n` - The number of positions to rotate
    ///
    /// # Returns
    /// A new `Integer` containing the rotated value.
    pub const fn rotate_left(&self, n: u32) -> Self {
        Self(self.0.rotate_left(n))
    }

    /// Performs a right rotation of the bits in the integer.
    ///
    /// # Parameters
    /// * `n` - The number of positions to rotate
    ///
    /// # Returns
    /// A new `Integer` containing the rotated value.
    pub const fn rotate_right(&self, n: u32) -> Self {
        Self(self.0.rotate_right(n))
    }

    /// Swaps the byte order of the integer.
    ///
    /// # Returns
    /// A new `Integer` containing the swapped value.
    pub const fn swap_bytes(&self) -> Self {
        Self(self.0.swap_bytes())
    }

    /// Reverses the bits in the integer.
    ///
    /// # Returns
    /// A new `Integer` containing the reversed value.
    pub const fn reverese_bits(&self) -> Self {
        Self(self.0.reverse_bits())
    }

    /// Computes the absolute value of the integer, allowing for overflow.
    ///
    /// # Returns
    /// A tuple containing the absolute value and a boolean indicating overflow.
    pub const fn overflowing_abs(&self) -> (Self, bool) {
        if self.0 < 0 {
            let abs_value = -self.0;
            (Integer(abs_value), true)
        } else {
            (*self, false)
        }
    }

    /// Performs addition, allowing for overflow.
    ///
    /// # Parameters
    /// * `other` - The value to add to this integer
    ///
    /// # Returns
    /// A tuple containing the sum and a boolean indicating overflow.
    pub const fn overflowing_add(&self, other: &Self) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_add(other.0);
        (Integer(result), overflow)
    }

    /// Performs addition with an unsigned value, allowing for overflow.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to add to this integer
    ///
    /// # Returns
    /// A tuple containing the sum and a boolean indicating overflow.
    pub const fn overflowwing_add_unsigned(&self, rhs: u128) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_add(rhs as i128);
        (Integer(result), overflow)
    }

    /// Performs division, allowing for overflow.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A tuple containing the quotient and a boolean indicating overflow.
    pub const fn overflowing_div(&self, other: &Self) -> (Self, bool) {
        if other.0 == 0 {
            panic!("Division by zero");
        }
        let (result, overflow) = self.0.overflowing_div(other.0);
        (Integer(result), overflow)
    }

    /// Performs Euclidean division, allowing for overflow.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A tuple containing the quotient and a boolean indicating overflow.
    pub const fn overflowing_div_euclid(&self, other: &Self) -> (Self, bool) {
        if other.0 == 0 {
            panic!("Division by zero");
        }
        let (result, overflow) = self.0.overflowing_div_euclid(other.0);
        (Integer(result), overflow)
    }

    /// Performs multiplication, allowing for overflow.
    ///
    /// # Parameters
    /// * `other` - The value to multiply this integer by
    ///
    /// # Returns
    /// A tuple containing the product and a boolean indicating overflow.
    pub const fn overflowing_mul(&self, other: &Self) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_mul(other.0);
        (Integer(result), overflow)
    }

    /// Performs negation, allowing for overflow.
    ///
    /// # Returns
    /// A tuple containing the negated value and a boolean indicating overflow.
    pub const fn overflowing_neg(&self) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_neg();
        (Integer(result), overflow)
    }

    /// Performs exponentiation, allowing for overflow.
    ///
    /// # Parameters
    /// * `exp` - The exponent
    ///
    /// # Returns
    /// A tuple containing the result and a boolean indicating overflow.
    pub const fn overflowing_pow(&self, exp: u32) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_pow(exp);
        (Integer(result), overflow)
    }

    /// Performs remainder, allowing for overflow.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A tuple containing the remainder and a boolean indicating overflow.
    pub const fn overflowing_rem(&self, other: &Self) -> (Self, bool) {
        if other.0 == 0 {
            panic!("Division by zero");
        }
        let (result, overflow) = self.0.overflowing_rem(other.0);
        (Integer(result), overflow)
    }

    /// Performs Euclidean remainder, allowing for overflow.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A tuple containing the remainder and a boolean indicating overflow.
    pub const fn overflowing_rem_euclid(&self, other: &Self) -> (Self, bool) {
        if other.0 == 0 {
            panic!("Division by zero");
        }
        let (result, overflow) = self.0.overflowing_rem_euclid(other.0);
        (Integer(result), overflow)
    }

    /// Performs left shift, allowing for overflow.
    ///
    /// # Parameters
    /// * `rhs` - The number of positions to shift
    ///
    /// # Returns
    /// A tuple containing the shifted value and a boolean indicating overflow.
    pub const fn overflowing_shl(&self, rhs: u32) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_shl(rhs);
        (Integer(result), overflow)
    }

    /// Performs right shift, allowing for overflow.
    ///
    /// # Parameters
    /// * `rhs` - The number of positions to shift
    ///
    /// # Returns
    /// A tuple containing the shifted value and a boolean indicating overflow.
    pub const fn overflowing_shr(&self, rhs: u32) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_shr(rhs);
        (Integer(result), overflow)
    }

    /// Performs subtraction, allowing for overflow.
    ///
    /// # Parameters
    /// * `other` - The value to subtract from this integer
    ///
    /// # Returns
    /// A tuple containing the difference and a boolean indicating overflow.
    pub const fn overflowing_sub(&self, other: &Self) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_sub(other.0);
        (Integer(result), overflow)
    }

    /// Performs subtraction with an unsigned value, allowing for overflow.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to subtract from this integer
    ///
    /// # Returns
    /// A tuple containing the difference and a boolean indicating overflow.
    pub const fn overflowing_sub_unsigned(&self, rhs: u128) -> (Self, bool) {
        let (result, overflow) = self.0.overflowing_sub(rhs as i128);
        (Integer(result), overflow)
    }

    /// Raises the integer to the power of the given exponent.
    ///
    /// Computes the result of exponentiation using the underlying i128 value.
    ///
    /// # Parameters
    /// * `exp` - The exponent to raise this integer to
    ///
    /// # Returns
    /// The result of the exponentiation as an i128.
    pub const fn pow(&self, exp: u32) -> i128 {
        self.0.pow(exp)
    }

    /// Calculates the Euclidean remainder of division.
    ///
    /// Unlike the standard remainder operation, the Euclidean remainder
    /// is always non-negative for a positive divisor.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A new `Integer` containing the Euclidean remainder.
    ///
    /// # Panics
    /// Panics if `other` is zero.
    pub const fn rem_euclid(&self, other: &Self) -> Self {
        if other.0 == 0 {
            panic!("Division by zero");
        }
        Integer(self.0.rem_euclid(other.0))
    }

    /// Reverses the order of bits in the integer.
    ///
    /// # Returns
    /// A new `Integer` with all bits in reverse order.
    pub const fn reverse_bits(&self) -> Self {
        Integer(self.0.reverse_bits())
    }

    /// Returns the absolute value of the integer, saturating at the numeric bounds.
    ///
    /// Unlike `abs()`, this method will not panic if the absolute value cannot be represented.
    ///
    /// # Returns
    /// A new `Integer` with the absolute value, or the maximum value if out of range.
    pub const fn saturating_abs(&self) -> Self {
        if self.0 < 0 {
            Integer(-self.0)
        } else {
            *self
        }
    }

    /// Performs saturating addition.
    ///
    /// Returns the sum, saturating at the numeric bounds instead of overflowing.
    ///
    /// # Parameters
    /// * `other` - The value to add to this integer
    ///
    /// # Returns
    /// A new `Integer` with the saturated sum.
    pub const fn saturating_add(&self, other: &Self) -> Self {
        let result = self.0.saturating_add(other.0);
        Integer(result)
    }

    /// Performs saturating addition with an unsigned value.
    ///
    /// Returns the sum, saturating at the numeric bounds instead of overflowing.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to add to this integer
    ///
    /// # Returns
    /// A new `Integer` with the saturated sum.
    pub const fn saturating_add_unsigned(&self, rhs: u128) -> Self {
        let result = self.0.saturating_add(rhs as i128);
        Integer(result)
    }

    /// Performs saturating division.
    ///
    /// Returns the quotient, saturating at the numeric bounds.
    /// Returns i128::MAX for division by zero instead of panicking.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A new `Integer` with the saturated quotient.
    pub const fn saturating_div(&self, other: &Self) -> Self {
        if other.0 == 0 {
            return Integer(i128::MAX);
        }
        Integer(self.0.saturating_div(other.0))
    }

    /// Performs saturating multiplication.
    ///
    /// Returns the product, saturating at the numeric bounds instead of overflowing.
    ///
    /// # Parameters
    /// * `other` - The value to multiply this integer by
    ///
    /// # Returns
    /// A new `Integer` with the saturated product.
    pub const fn saturating_mul(&self, other: &Self) -> Self {
        let result = self.0.saturating_mul(other.0);
        Integer(result)
    }

    /// Performs saturating negation.
    ///
    /// Returns the negation, saturating at the numeric bounds instead of overflowing.
    ///
    /// # Returns
    /// A new `Integer` with the saturated negation.
    pub const fn saturating_neg(&self) -> Self {
        let result = self.0.saturating_neg();
        Integer(result)
    }

    /// Performs saturating exponentiation.
    ///
    /// Returns the result of exponentiation, saturating at the numeric bounds 
    /// instead of overflowing.
    ///
    /// # Parameters
    /// * `exp` - The exponent
    ///
    /// # Returns
    /// A new `Integer` with the saturated exponentiation result.
    pub const fn saturating_pow(&self, exp: u32) -> Self {
        let result = self.0.saturating_pow(exp);
        Integer(result)
    }

    /// Performs saturating subtraction.
    ///
    /// Returns the difference, saturating at the numeric bounds instead of overflowing.
    ///
    /// # Parameters
    /// * `other` - The value to subtract from this integer
    ///
    /// # Returns
    /// A new `Integer` with the saturated difference.
    pub const fn saturating_sub(&self, other: &Self) -> Self {
        let result = self.0.saturating_sub(other.0);
        Integer(result)
    }

    /// Performs saturating subtraction with an unsigned value.
    ///
    /// Returns the difference, saturating at the numeric bounds instead of overflowing.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to subtract from this integer
    ///
    /// # Returns
    /// A new `Integer` with the saturated difference.
    pub const fn saturating_sub_unsigned(&self, rhs: u128) -> Self {
        let result = self.0.saturating_sub(rhs as i128);
        Integer(result)
    }

    /// Returns the sign of the integer as -1, 0, or 1.
    ///
    /// # Returns
    /// * Integer(-1) if the value is negative
    /// * Integer(0) if the value is zero
    /// * Integer(1) if the value is positive
    pub const fn signum(&self) -> Self {
        if self.0 < 0 {
            Integer(-1)
        } else if self.0 > 0 {
            Integer(1)
        } else {
            Integer(0)
        }
    }

    /// Converts the integer to big-endian byte order.
    ///
    /// # Returns
    /// A new `Integer` with bytes in big-endian order.
    pub const fn to_be(self) -> Self {
        if cfg!(target_endian = "big") {
            self
        } else {
            self.swap_bytes()
        }
    }

    /// Converts the integer to a byte array in big-endian byte order.
    ///
    /// # Returns
    /// A 16-byte array containing the integer value in big-endian byte order.
    pub const fn to_be_bytes(&self) -> [u8; 16] {
        if cfg!(target_endian = "big") {
            self.0.to_be_bytes()
        } else {
            self.0.to_le_bytes()
        }
    }

    /// Converts the integer to little-endian byte order.
    ///
    /// # Returns
    /// A new `Integer` with bytes in little-endian order.
    pub const fn to_le(self) -> Self {
        if cfg!(target_endian = "little") {
            self
        } else {
            self.swap_bytes()
        }
    }

    /// Converts the integer to a byte array in little-endian byte order.
    ///
    /// # Returns
    /// A 16-byte array containing the integer value in little-endian byte order.
    pub const fn to_le_bytes(&self) -> [u8; 16] {
        if cfg!(target_endian = "little") {
            self.0.to_le_bytes()
        } else {
            self.0.to_be_bytes()
        }
    }

    /// Converts the integer to a byte array in native-endian byte order.
    ///
    /// # Returns
    /// A 16-byte array containing the integer value in the endianness of the current platform.
    pub const fn to_ne_bytes(&self) -> [u8; 16] {
        self.0.to_ne_bytes()
    }

    /// Returns the absolute value of the integer as an unsigned value.
    ///
    /// Similar to `abs()` but semantically indicates the result is always non-negative.
    ///
    /// # Returns
    /// A new `Integer` containing the absolute value.
    pub const fn unsigned_abs(&self) -> Self {
        if self.0 < 0 {
            Integer(-self.0)
        } else {
            *self
        }
    }

    /// Returns the absolute value of the integer, wrapping on overflow.
    ///
    /// # Returns
    /// A new `Integer` containing the wrapped absolute value.
    pub const fn wrapping_abs(&self) -> Self {
        if self.0 < 0 {
            Integer(-self.0)
        } else {
            *self
        }
    }

    /// Performs wrapping addition.
    ///
    /// Returns `self + other`, wrapping around at the boundaries of the type.
    ///
    /// # Parameters
    /// * `other` - The value to add to this integer
    ///
    /// # Returns
    /// A new `Integer` with the wrapped sum.
    pub const fn wrapping_add(&self, other: &Self) -> Self {
        let result = self.0.wrapping_add(other.0);
        Integer(result)
    }

    /// Performs wrapping addition with an unsigned value.
    ///
    /// Returns `self + rhs as i128`, wrapping around at the boundaries of the type.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to add to this integer
    ///
    /// # Returns
    /// A new `Integer` with the wrapped sum.
    pub const fn wrapping_add_unsigned(&self, rhs: u128) -> Self {
        let result = self.0.wrapping_add(rhs as i128);
        Integer(result)
    }

    /// Performs wrapping division.
    ///
    /// Returns `self / other`, wrapping around at the boundaries of the type.
    /// Returns i128::MAX for division by zero instead of panicking.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A new `Integer` with the wrapped quotient.
    pub const fn wrapping_div(&self, other: &Self) -> Self {
        if other.0 == 0 {
            return Integer(i128::MAX);
        }
        Integer(self.0.wrapping_div(other.0))
    }

    /// Performs wrapping Euclidean division.
    ///
    /// Returns `self.div_euclid(other)`, wrapping around at the boundaries of the type.
    /// Returns i128::MAX for division by zero instead of panicking.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A new `Integer` with the wrapped Euclidean quotient.
    pub const fn wrapping_div_euclid(&self, other: &Self) -> Self {
        if other.0 == 0 {
            return Integer(i128::MAX);
        }
        Integer(self.0.wrapping_div_euclid(other.0))
    }

    /// Performs wrapping multiplication.
    ///
    /// Returns `self * other`, wrapping around at the boundaries of the type.
    ///
    /// # Parameters
    /// * `other` - The value to multiply this integer by
    ///
    /// # Returns
    /// A new `Integer` with the wrapped product.
    pub const fn wrapping_mul(&self, other: &Self) -> Self {
        let result = self.0.wrapping_mul(other.0);
        Integer(result)
    }

    /// Performs wrapping negation.
    ///
    /// Returns `-self`, wrapping around at the boundaries of the type.
    ///
    /// # Returns
    /// A new `Integer` with the wrapped negation.
    pub const fn wrapping_neg(&self) -> Self {
        let result = self.0.wrapping_neg();
        Integer(result)
    }

    /// Performs wrapping exponentiation.
    ///
    /// Returns `self.pow(exp)`, wrapping around at the boundaries of the type.
    ///
    /// # Parameters
    /// * `exp` - The exponent
    ///
    /// # Returns
    /// A new `Integer` with the wrapped exponentiation result.
    pub const fn wrapping_pow(&self, exp: u32) -> Self {
        let result = self.0.wrapping_pow(exp);
        Integer(result)
    }

    /// Performs wrapping remainder.
    ///
    /// Returns `self % other`, wrapping around at the boundaries of the type.
    /// Returns i128::MAX for division by zero instead of panicking.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A new `Integer` with the wrapped remainder.
    pub const fn wrapping_rem(&self, other: &Self) -> Self {
        if other.0 == 0 {
            return Integer(i128::MAX);
        }
        Integer(self.0.wrapping_rem(other.0))
    }

    /// Performs wrapping Euclidean remainder.
    ///
    /// Returns `self.rem_euclid(other)`, wrapping around at the boundaries of the type.
    /// Returns i128::MAX for division by zero instead of panicking.
    ///
    /// # Parameters
    /// * `other` - The value to divide this integer by
    ///
    /// # Returns
    /// A new `Integer` with the wrapped Euclidean remainder.
    pub const fn wrapping_rem_euclid(&self, other: &Self) -> Self {
        if other.0 == 0 {
            return Integer(i128::MAX);
        }
        Integer(self.0.wrapping_rem_euclid(other.0))
    }

    /// Performs a wrapping left shift operation.
    ///
    /// Returns the result of shifting the bits in the inner value to the left by `rhs` positions.
    /// If `rhs` exceeds the length of the value, the bits are wrapped around.
    ///
    /// # Parameters
    /// * `rhs` - The number of positions to shift
    ///
    /// # Returns
    /// A new `Integer` with the shifted value
    pub const fn wrapping_shl(&self, rhs: u32) -> Self {
        let result = self.0.wrapping_shl(rhs);
        Integer(result)
    }

    /// Performs a wrapping right shift operation.
    ///
    /// Returns the result of shifting the bits in the inner value to the right by `rhs` positions.
    /// If `rhs` exceeds the length of the value, the bits are wrapped around.
    ///
    /// # Parameters
    /// * `rhs` - The number of positions to shift
    ///
    /// # Returns
    /// A new `Integer` with the shifted value
    pub const fn wrapping_shr(&self, rhs: u32) -> Self {
        let result = self.0.wrapping_shr(rhs);
        Integer(result)
    }

    /// Performs wrapping subtraction.
    ///
    /// Returns `self - other`, wrapping around at the boundaries of the type.
    ///
    /// # Parameters
    /// * `other` - The value to subtract from this integer
    ///
    /// # Returns
    /// A new `Integer` with the wrapped difference
    pub const fn wrapping_sub(&self, other: &Self) -> Self {
        let result = self.0.wrapping_sub(other.0);
        Integer(result)
    }

    /// Performs wrapping subtraction with an unsigned value.
    ///
    /// Returns `self - rhs as i128`, wrapping around at the boundaries of the type.
    ///
    /// # Parameters
    /// * `rhs` - The unsigned value to subtract from this integer
    ///
    /// # Returns
    /// A new `Integer` with the wrapped difference
    pub const fn wrapping_sub_unsigned(&self, rhs: u128) -> Self {
        let result = self.0.wrapping_sub(rhs as i128);
        Integer(result)
    }

    /// Returns the CBOR info byte for the integer.
    ///
    /// Calculates the appropriate CBOR additional information value based on the
    /// integer's serialized representation length.
    ///
    /// # Returns
    /// * `Ok(u8)` - The CBOR info byte
    /// * `Err(NumbersError)` - If the integer has an invalid CBOR length
    pub fn cbor_info(&self) -> Result<u8, crate::error::NumbersError> {
        let length = self.serialized_len();
        match length {
            1 => Ok((self.0 & 0x1F) as u8),
            2 => Ok(0x18),
            3 => Ok(0x19),
            5 => Ok(0x1A),
            9 => Ok(0x1B),
            _ => Err(crate::error::NumbersError::InvalidCBORIntLength { length }),
        }
    }

    /// Checks if this integer value fits within the range of a specific integer type.
    ///
    /// # Type Parameters
    /// * `T` - The target integer type that implements `IntegerType`
    ///
    /// # Returns
    /// `true` if the value can be represented by type `T` without overflow, otherwise `false`
    pub fn fits_into<T: IntegerType>(&self) -> bool {
        let val = self.0;
        val >= T::min_value().as_i128() && val <= T::max_value().as_i128()
    }
}

impl Add for Integer {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Integer(self.0 + other.0)
    }
}

impl AddAssign for Integer {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl Mul for Integer {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Integer(self.0 * other.0)
    }
}
impl MulAssign for Integer {
    fn mul_assign(&mut self, other: Self) {
        self.0 *= other.0;
    }
}

impl Sub for Integer {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        Integer(self.0 - other.0)
    }
}

impl SubAssign for Integer {
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl Neg for Integer {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Integer(-self.0)
    }
}

impl Div for Integer {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        Integer(self.0 / other.0)
    }
}

impl DivAssign for Integer {
    fn div_assign(&mut self, other: Self) {
        self.0 /= other.0;
    }
}

impl BitAnd for Integer {
    type Output = Self;

    fn bitand(self, other: Self) -> Self::Output {
        Integer(self.0 & other.0)
    }
}

impl BitAndAssign for Integer {
    fn bitand_assign(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

impl BitOr for Integer {
    type Output = Self;

    fn bitor(self, other: Self) -> Self::Output {
        Integer(self.0 | other.0)
    }
}

impl BitOrAssign for Integer {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl BitXor for Integer {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self::Output {
        Integer(self.0 ^ other.0)
    }
}

impl BitXorAssign for Integer {
    fn bitxor_assign(&mut self, other: Self) {
        self.0 ^= other.0;
    }
}

impl Rem for Integer {
    type Output = Self;

    fn rem(self, other: Self) -> Self::Output {
        Integer(self.0 % other.0)
    }
}

impl RemAssign for Integer {
    fn rem_assign(&mut self, other: Self) {
        self.0 %= other.0;
    }
}

impl Shl for Integer {
    type Output = Self;

    fn shl(self, other: Self) -> Self::Output {
        Integer(self.0 << other.0)
    }
}

impl ShlAssign for Integer {
    fn shl_assign(&mut self, other: Self) {
        self.0 <<= other.0;
    }
}

impl Shr for Integer {
    type Output = Self;

    fn shr(self, other: Self) -> Self::Output {
        Integer(self.0 >> other.0)
    }
}

impl ShrAssign for Integer {
    fn shr_assign(&mut self, other: Self) {
        self.0 >>= other.0;
    }
}

impl WrappedInteger for Integer {
    type Inner = i128;

    fn inner(&self) -> Self::Inner {
        self.0
    }
}

impl Display for Integer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for Integer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Integer({})", self.0)
    }
}

impl Deref for Integer {
    type Target = i128;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Integer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<i128> for Integer {
    fn as_ref(&self) -> &i128 {
        &self.0
    }
}

impl AsMut<i128> for Integer {
    fn as_mut(&mut self) -> &mut i128 {
        &mut self.0
    }
}

impl FromStr for Integer {
    type Err = NumbersError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<i128>() {
            Ok(value) => Ok(Integer(value)),
            Err(_) => Err(crate::error::NumbersError::ParseIntError),
        }
    }
}

impl Hash for Integer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

macro_rules! impl_integer_cast {
    ($($t:ty),+ $(,)*) => {
        $(
            impl From<$t> for Integer {
                fn from(value: $t) -> Self {
                    Integer(value as i128)
                }
            }

            impl TryFrom<Integer> for $t {
                type Error = crate::error::NumbersError;

                fn try_from(value: Integer) -> Result<Self, Self::Error> {
                    if value.0 > <$t>::MAX as i128 {
                        return Err(crate::error::NumbersError::ValueExceedsType);
                    }

                    Ok(value.0 as $t)
                }
            }
        )+
    }
}

all_integers!(impl_integer_cast);

impl From<usize> for Integer {
    fn from(value: usize) -> Self {
        Integer(value as i128)
    }
}

impl From<isize> for Integer {
    fn from(value: isize) -> Self {
        Integer(value as i128)
    }
}

impl TryFrom<Integer> for usize {
    type Error = crate::error::NumbersError;

    fn try_from(value: Integer) -> Result<Self, Self::Error> {
        #[cfg(target_pointer_width = "32")]
        if value.0 > u32::MAX as i128 {
            return Err(crate::error::NumbersError::ArchitectureLimitExceeded {
                bits: 32,
                max_value: u32::MAX.to_string(),
            });
        }

        #[cfg(target_pointer_width = "64")]
        if value.0 > u64::MAX as i128 {
            return Err(crate::error::NumbersError::ArchitectureLimitExceeded {
                bits: 64,
                max_value: u64::MAX.to_string(),
            });
        }

        if value.0 < 0 {
            return Err(crate::error::NumbersError::NegativeAsUsize);
        }

        Ok(value.0 as usize)
    }
}

impl TryFrom<Integer> for isize {
    type Error = crate::error::NumbersError;

    fn try_from(value: Integer) -> Result<Self, Self::Error> {
        #[cfg(target_pointer_width = "32")]
        if value.0 > i32::MAX as i128 {
            return Err(crate::error::NumbersError::ArchitectureLimitExceeded {
                bits: 32,
                max_value: i32::MAX.to_string(),
            });
        }

        #[cfg(target_pointer_width = "64")]
        if value.0 > i64::MAX as i128 {
            return Err(crate::error::NumbersError::ArchitectureLimitExceeded {
                bits: 64,
                max_value: i64::MAX.to_string(),
            });
        }

        Ok(value.0 as isize)
    }
}

impl Serialize for Integer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize to the smallest integer type possible
        // based on the value of the integer.

        let number = self.0;

        // Use the same range logic as in serialized_len
        if (-24..24).contains(&number) {
            // Small values
            return if number.is_negative() {
                serializer.serialize_i8(number as i8)
            } else {
                serializer.serialize_u8(number as u8)
            };
        }

        // Use the same bit-width detection as serialized_len
        match number.abs().ilog2() {
            0..=7 => {
                if number.is_negative() {
                    serializer.serialize_i8(number as i8)
                } else {
                    serializer.serialize_u8(number as u8)
                }
            }
            8..=15 => {
                if number.is_negative() {
                    serializer.serialize_i16(number as i16)
                } else {
                    serializer.serialize_u16(number as u16)
                }
            }
            16..=31 => {
                if number.is_negative() {
                    serializer.serialize_i32(number as i32)
                } else {
                    serializer.serialize_u32(number as u32)
                }
            }
            32..=63 => {
                if number.is_negative() {
                    serializer.serialize_i64(number as i64)
                } else {
                    serializer.serialize_u64(number as u64)
                }
            }
            _ => {
                if number.is_negative() {
                    serializer.serialize_i128(number)
                } else {
                    serializer.serialize_u128(number as u128)
                }
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Integer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IntegerVisitor;

        impl<'de> serde::de::Visitor<'de> for IntegerVisitor {
            type Value = Integer;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer")
            }

            fn visit_i8<E>(self, value: i8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Integer(value as i128))
            }

            fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Integer(value as i128))
            }

            fn visit_i16<E>(self, value: i16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Integer(value as i128))
            }

            fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Integer(value as i128))
            }

            fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Integer(value as i128))
            }

            fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Integer(value as i128))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                #[cfg(target_pointer_width = "32")]
                if value > i32::MAX as i64 {
                    return Err(E::custom(format!(
                        "Value {} exceeds maximum ({}) for 32-bit architecture",
                        value,
                        i32::MAX
                    )));
                }

                Ok(Integer(value as i128))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                #[cfg(target_pointer_width = "32")]
                if value > u32::MAX as u64 {
                    return Err(E::custom(format!(
                        "Value {} exceeds maximum ({}) for 32-bit architecture",
                        value,
                        u32::MAX
                    )));
                }

                Ok(Integer(value as i128))
            }

            fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Integer(value))
            }

            fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value > i128::MAX as u128 {
                    return Err(E::custom("value out of range for i128"));
                }
                Ok(Integer(value as i128))
            }

            fn visit_char<E>(self, v: char) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.is_ascii() {
                    return Ok(Integer(v as u8 as i128));
                }
                if v.is_digit(10) {
                    return Ok(Integer(v.to_digit(10).unwrap() as i128));
                }

                Err(E::custom("invalid char for integer"))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_borrowed_str(v)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.is_empty() {
                    return Err(E::custom("empty string"));
                }
                if v.len() > 16 {
                    return Err(E::custom("string too long"));
                }
                let mut value = 0u128;
                for c in v.chars() {
                    if !c.is_digit(10) {
                        return Err(E::custom("invalid character in string"));
                    }
                    value = (value * 10) + (c.to_digit(10).unwrap() as u128);
                }
                if value > i128::MAX as u128 {
                    return Err(E::custom("value out of range for i128"));
                }
                Ok(Integer(value as i128))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_borrowed_str(v.as_str())
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_borrowed_bytes(v)
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 0 {
                    return Err(E::custom("empty byte array"));
                }
                if v.len() > 16 {
                    return Err(E::custom("byte array too long"));
                }
                let mut value = 0u128;
                for &byte in v.iter() {
                    value = (value << 8) | byte as u128;
                }
                if value > i128::MAX as u128 {
                    return Err(E::custom("value out of range for i128"));
                }
                Ok(Integer(value as i128))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_borrowed_bytes(v.as_slice())
            }
        }

        deserializer
            .deserialize_any(IntegerVisitor)
            .map_err(|_| serde::de::Error::custom("failed to deserialize integer"))
    }
}

#[cfg(test)]
mod tests {
    use std::u32;

    use super::*;

    #[test]
    fn test_integer_serialization_with_ciborium_one_byte() {
        let expected: Vec<u8> = vec![0x16]; // CBOR encoding for 22

        let integer = Integer(22);

        let mut buffer = Vec::new();
        ciborium::into_writer(&integer, &mut buffer).unwrap();

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_integer_deserialization_with_ciborium_one_byte() {
        let expected = Integer(22);

        let serialized: Vec<u8> = vec![0x16]; // CBOR encoding for 22
        let deserialized: Integer = ciborium::from_reader(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_integer_serialization_with_ciborium_two_byte() {
        let expected: Vec<u8> = vec![0x18, 0x2A]; // CBOR encoding for 42

        let integer = Integer(42);

        let mut buffer = Vec::new();
        ciborium::into_writer(&integer, &mut buffer).unwrap();

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_integer_deserialization_with_ciborium_two_byte() {
        let expected = Integer(42);

        let serialized: Vec<u8> = vec![0x18, 0x2A]; // CBOR encoding for 42
        let deserialized: Integer = ciborium::from_reader(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_integer_serialization_with_ciborium_three_byte() {
        let expected: Vec<u8> = vec![0x19, 0x40, 0x76]; // CBOR encoding for 16502

        let integer = Integer(16502);

        let mut buffer = Vec::new();
        ciborium::into_writer(&integer, &mut buffer).unwrap();

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_integer_deserialization_with_ciborium_three_byte() {
        let expected = Integer(16502);

        let serialized: Vec<u8> = vec![0x19, 0x40, 0x76]; // CBOR encoding for 16502
        let deserialized: Integer = ciborium::from_reader(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_integer_serialization_with_ciborium_five_byte() {
        let expected: Vec<u8> = vec![0x1A, 0x01, 0x00, 0x00, 0x00]; // CBOR encoding for 16777216

        let integer = Integer(16777216);

        let mut buffer = Vec::new();
        ciborium::into_writer(&integer, &mut buffer).unwrap();

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_integer_deserialization_with_ciborium_five_byte() {
        let expected = Integer(16777216);

        let serialized: Vec<u8> = vec![0x1A, 0x01, 0x00, 0x00, 0x00]; // CBOR encoding for 16777216
        let deserialized: Integer = ciborium::from_reader(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_integer_serialization_from_negative_five_byte() {
        let expected: Vec<u8> = vec![0x3A, 0x00, 0xFF, 0xFF, 0xFF]; // CBOR encoding for -16777216

        let integer = Integer(-16777216);

        let mut buffer = Vec::new();
        ciborium::into_writer(&integer, &mut buffer).unwrap();

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_integer_serialization_with_ciborium_nine_byte() {
        let expected: Vec<u8> = vec![0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // CBOR encoding for 4294967296
        let integer = Integer(4294967296);
        let mut buffer = Vec::new();
        ciborium::into_writer(&integer, &mut buffer).unwrap();
        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_integer_deserialization_with_ciborium_nine_byte() {
        let expected = Integer(4294967296);

        let serialized: Vec<u8> = vec![0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // CBOR encoding for 4294967296
        let deserialized: Integer = ciborium::from_reader(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_integer_serialization_with_serde() {
        let integer = Integer(42);
        let serialized = serde_json::to_string(&integer).unwrap();
        let deserialized: Integer = serde_json::from_str(&serialized).unwrap();
        assert_eq!(integer, deserialized);
    }

    #[test]
    fn test_integer_deserialization_with_serde() {
        let serialized = r#"42"#; // JSON encoding for 42
        let deserialized: Integer = serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized, Integer(42));
    }

    #[test]
    fn test_integer_new_with_types() {
        let my_u8_int = Integer::new(1u8);
        let my_u16_int = Integer::new(2u16);
        let my_u32_int = Integer::new(64u32);
        let my_u64_int = Integer::new(43u64);
        let my_u128_int = Integer::new(15u128);

        let my_i8_int = Integer::new(1i8);
        let my_i16_int = Integer::new(2i16);
        let my_i32_int = Integer::new(64i32);
        let my_i64_int = Integer::new(43i64);
        let my_i128_int = Integer::new(15i128);

        assert_eq!(my_u8_int.inner(), 1i128);
        assert_eq!(my_u16_int.inner(), 2i128);
        assert_eq!(my_u32_int.inner(), 64i128);
        assert_eq!(my_u64_int.inner(), 43i128);
        assert_eq!(my_u128_int.inner(), 15i128);

        assert_eq!(my_i8_int.inner(), 1i128);
        assert_eq!(my_i16_int.inner(), 2i128);
        assert_eq!(my_i32_int.inner(), 64i128);
        assert_eq!(my_i64_int.inner(), 43i128);
        assert_eq!(my_i128_int.inner(), 15i128);
    }
    
    #[test]
    fn test_fits_into_u8() {
        // Values within u8 range
        assert!(Integer(0).fits_into::<u8>());
        assert!(Integer(1).fits_into::<u8>());
        assert!(Integer(127).fits_into::<u8>());
        assert!(Integer(255).fits_into::<u8>());
        
        // Values outside u8 range
        assert!(!Integer(-1).fits_into::<u8>());
        assert!(!Integer(256).fits_into::<u8>());
        assert!(!Integer(i128::MAX).fits_into::<u8>());
        assert!(!Integer(i128::MIN).fits_into::<u8>());
    }
    
    #[test]
    fn test_fits_into_i8() {
        // Values within i8 range
        assert!(Integer(-128).fits_into::<i8>());
        assert!(Integer(-1).fits_into::<i8>());
        assert!(Integer(0).fits_into::<i8>());
        assert!(Integer(1).fits_into::<i8>());
        assert!(Integer(127).fits_into::<i8>());
        
        // Values outside i8 range
        assert!(!Integer(-129).fits_into::<i8>());
        assert!(!Integer(128).fits_into::<i8>());
        assert!(!Integer(i128::MAX).fits_into::<i8>());
        assert!(!Integer(i128::MIN).fits_into::<i8>());
    }
    
    #[test]
    fn test_fits_into_u16() {
        // Values within u16 range
        assert!(Integer(0).fits_into::<u16>());
        assert!(Integer(1).fits_into::<u16>());
        assert!(Integer(32767).fits_into::<u16>());
        assert!(Integer(65535).fits_into::<u16>());
        
        // Values outside u16 range
        assert!(!Integer(-1).fits_into::<u16>());
        assert!(!Integer(65536).fits_into::<u16>());
        assert!(!Integer(i128::MAX).fits_into::<u16>());
        assert!(!Integer(i128::MIN).fits_into::<u16>());
    }
    
    #[test]
    fn test_fits_into_i16() {
        // Values within i16 range
        assert!(Integer(-32768).fits_into::<i16>());
        assert!(Integer(-1).fits_into::<i16>());
        assert!(Integer(0).fits_into::<i16>());
        assert!(Integer(1).fits_into::<i16>());
        assert!(Integer(32767).fits_into::<i16>());
        
        // Values outside i16 range
        assert!(!Integer(-32769).fits_into::<i16>());
        assert!(!Integer(32768).fits_into::<i16>());
        assert!(!Integer(i128::MAX).fits_into::<i16>());
        assert!(!Integer(i128::MIN).fits_into::<i16>());
    }
    
    #[test]
    fn test_fits_into_u32() {
        // Values within u32 range
        assert!(Integer(0).fits_into::<u32>());
        assert!(Integer(1).fits_into::<u32>());
        assert!(Integer(2147483647).fits_into::<u32>());
        assert!(Integer(4294967295).fits_into::<u32>());
        
        // Values outside u32 range
        assert!(!Integer(-1).fits_into::<u32>());
        assert!(!Integer(4294967296).fits_into::<u32>());
        assert!(!Integer(i128::MAX).fits_into::<u32>());
        assert!(!Integer(i128::MIN).fits_into::<u32>());
    }
    
    #[test]
    fn test_fits_into_i32() {
        // Values within i32 range
        assert!(Integer(-2147483648).fits_into::<i32>());
        assert!(Integer(-1).fits_into::<i32>());
        assert!(Integer(0).fits_into::<i32>());
        assert!(Integer(1).fits_into::<i32>());
        assert!(Integer(2147483647).fits_into::<i32>());
        
        // Values outside i32 range
        assert!(!Integer(-2147483649).fits_into::<i32>());
        assert!(!Integer(2147483648).fits_into::<i32>());
        assert!(!Integer(i128::MAX).fits_into::<i32>());
        assert!(!Integer(i128::MIN).fits_into::<i32>());
    }
    
    #[test]
    fn test_fits_into_u64() {
        // Values within u64 range
        assert!(Integer(0).fits_into::<u64>());
        assert!(Integer(1).fits_into::<u64>());
        assert!(Integer(9223372036854775807).fits_into::<u64>());
        assert!(Integer(18446744073709551615).fits_into::<u64>());
        
        // Values outside u64 range
        assert!(!Integer(-1).fits_into::<u64>());
        assert!(!Integer(18446744073709551616).fits_into::<u64>());
        assert!(!Integer(i128::MAX).fits_into::<u64>());
        assert!(!Integer(i128::MIN).fits_into::<u64>());
    }
    
    #[test]
    fn test_fits_into_i64() {
        // Values within i64 range
        assert!(Integer(-9223372036854775808).fits_into::<i64>());
        assert!(Integer(-1).fits_into::<i64>());
        assert!(Integer(0).fits_into::<i64>());
        assert!(Integer(1).fits_into::<i64>());
        assert!(Integer(9223372036854775807).fits_into::<i64>());
        
        // Values outside i64 range
        assert!(!Integer(-9223372036854775809).fits_into::<i64>());
        assert!(!Integer(9223372036854775808).fits_into::<i64>());
        assert!(!Integer(i128::MAX).fits_into::<i64>());
        assert!(!Integer(i128::MIN).fits_into::<i64>());
    }
    
    #[test]
    fn test_fits_into_u128() {
        // Values within u128 range
        assert!(Integer(0).fits_into::<u128>());
        assert!(Integer(1).fits_into::<u128>());
        assert!(Integer(i128::MAX).fits_into::<u128>());
        
        // Values outside u128 range
        assert!(!Integer(-1).fits_into::<u128>());
        assert!(!Integer(i128::MIN).fits_into::<u128>());
    }
    
    #[test]
    fn test_fits_into_i128() {
        // All i128 values fit into i128
        assert!(Integer(i128::MIN).fits_into::<i128>());
        assert!(Integer(-1).fits_into::<i128>());
        assert!(Integer(0).fits_into::<i128>());
        assert!(Integer(1).fits_into::<i128>());
        assert!(Integer(i128::MAX).fits_into::<i128>());
    }
    
    #[test]
    fn test_fits_into_edge_cases() {
        // Test with Integer::MAX and Integer::MIN constants
        assert!(Integer::MIN.fits_into::<i128>());
        assert!(!Integer::MIN.fits_into::<i64>());
        assert!(!Integer::MIN.fits_into::<i32>());
        
        assert!(Integer::MAX.fits_into::<i128>());
        assert!(!Integer::MAX.fits_into::<i64>());
        assert!(!Integer::MAX.fits_into::<u128>());
        
        // Test with specific edge values
        let max_i32_plus_1 = Integer(2147483648); // i32::MAX + 1
        assert!(!max_i32_plus_1.fits_into::<i32>());
        assert!(max_i32_plus_1.fits_into::<u32>());
        assert!(max_i32_plus_1.fits_into::<i64>());
        
        let min_i32_minus_1 = Integer(-2147483649); // i32::MIN - 1
        assert!(!min_i32_minus_1.fits_into::<i32>());
        assert!(min_i32_minus_1.fits_into::<i64>());
        assert!(!min_i32_minus_1.fits_into::<u64>());
    }
}
