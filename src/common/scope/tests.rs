/*
 * Copyright (c) 2022 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// Tests for text encoded scopes.
mod text {
    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString, vec, vec::Vec};
    use core::marker::PhantomData;

    use ciborium::value::Value;

    use crate::common::cbor_map::decode_scope;
    use crate::common::scope::{AifRestMethodSet, TextEncodedScope};
    use crate::error::{InvalidTextEncodedScopeError, ScopeFromValueError};
    use crate::{AifEncodedScope, Scope};

    #[test]
    fn test_scope_element_normal() -> Result<(), InvalidTextEncodedScopeError> {
        let simple = TextEncodedScope::try_from("this is a test")?;
        assert!(simple.elements().eq(vec!["this", "is", "a", "test"]));

        let single = TextEncodedScope::try_from("single")?;
        assert!(single.elements().eq(vec!["single"]));

        let third = TextEncodedScope::try_from("another quick test")?;
        assert!(third.elements().eq(vec!["another", "quick", "test"]));

        let array = TextEncodedScope::try_from(vec!["array", "test"])?;
        assert!(array.elements().eq(vec!["array", "test"]));

        let array_single = TextEncodedScope::try_from(vec!["justme"])?;
        assert!(array_single.elements().eq(vec!["justme"]));
        Ok(())
    }

    #[test]
    fn test_scope_elements_empty() {
        let empty_inputs: Vec<&str> = vec!["    ", " ", ""];

        for input in empty_inputs {
            assert!(TextEncodedScope::try_from(input).is_err());
        }

        let empty_arrays: Vec<Vec<&str>> = vec![
            vec![],
            vec![""],
            vec![" "],
            vec!["   "],
            vec!["", ""],
            vec!["", " "],
            vec!["", "   "],
            vec![" ", " "],
            vec![" ", ""],
            vec![" ", "   "],
            vec!["   ", "   "],
            vec!["   ", " "],
            vec!["   ", ""],
        ];

        for input in empty_arrays {
            assert!(!TextEncodedScope::try_from(input)
                .expect_err("must be error")
                .to_string()
                .is_empty());
        }
    }

    #[test]
    fn test_scope_elements_invalid_spaces() {
        let invalid_inputs = vec![
            "space at the end ",
            "spaces at the end   ",
            " space at the start",
            "   spaces at the start",
            " spaces at both ends ",
            "   spaces at both ends    ",
            "spaces   in the       middle",
            "   spaces   wherever  you    look   ",
        ];
        for input in invalid_inputs {
            assert!(!TextEncodedScope::try_from(input)
                .expect_err("must be error")
                .to_string()
                .is_empty());
        }
    }

    #[test]
    fn test_scope_elements_invalid_characters() {
        let invalid_inputs = vec![
            "\"",
            "\\",
            "a \" in between",
            "a \\ in between",
            " \" ",
            " \\ ",
            "within\"word",
            "within\\word",
        ];
        for input in invalid_inputs {
            assert!(!TextEncodedScope::try_from(input)
                .expect_err("must be error")
                .to_string()
                .is_empty());
        }

        let invalid_arrays = vec![
            vec!["space within"],
            vec!["more spaces within"],
            vec!["normal", "array", "but space"],
            vec!["normal", "but space", "array"],
            vec!["but space", "normal", "array"],
            vec!["\""],
            vec!["\\"],
            vec!["\"\\"],
            vec!["\" \\"],
            vec!["\\ \\"],
            vec!["\" \""],
            vec!["\\", "\\"],
            vec!["\"", "\""],
            vec!["\\", "\""],
            vec!["\"", "\\"],
            vec!["normal", "\\", "almost"],
            vec!["normal", "\"", "allowed"],
            vec!["normal", "in\"word\""],
            vec!["normal", "in\\word"],
        ];
        for input in invalid_arrays {
            assert!(!TextEncodedScope::try_from(input)
                .expect_err("must be error")
                .to_string()
                .is_empty());
        }
    }

    #[test]
    fn test_scope_value() -> Result<(), ScopeFromValueError> {
        let scope = Scope::try_from(vec!["one", "two", "three"])?;
        let value = Value::from(scope.clone());
        assert!(value.is_text());
        assert_eq!(value.as_text().expect("not a text"), "one two three");
        assert_eq!(Scope::try_from(value)?, scope);
        Ok(())
    }

    #[test]
    fn test_convert_invalid_value_to_scope() {
        assert!(decode_scope(Value::Bool(false)).is_err());
    }

    #[test]
    fn test_scope_invalid_try_from() {
        let scope = Scope::from(AifEncodedScope::from(vec![(
            "empty".to_string(),
            AifRestMethodSet::empty(),
        )]));
        let error = TextEncodedScope::try_from(scope).expect_err("expected error");
        assert_eq!(error.actual_type, "AifEncoded");
        assert_eq!(error.expected_type, "TextEncoded");
        assert_eq!(error.general_type, PhantomData::<Scope>::default());
    }
}

mod aif {
    use core::marker::PhantomData;

    use ciborium::de::from_reader;
    use ciborium::ser::into_writer;
    use enumflags2::{make_bitflags, BitFlags};

    #[cfg(not(feature = "std"))]
    use {
        alloc::string::{String, ToString},
        alloc::vec,
        alloc::vec::Vec,
    };

    use crate::common::scope::{AifEncodedScopeElement, AifRestMethod, AifRestMethodSet};
    use crate::error::InvalidAifEncodedScopeError;
    use crate::{AifEncodedScope, LibdcafEncodedScope, Scope};

    pub(crate) fn example_elements() -> (
        AifEncodedScopeElement,
        AifEncodedScopeElement,
        AifEncodedScopeElement,
        AifEncodedScopeElement,
    ) {
        let restricted = AifEncodedScopeElement::new("restricted".to_string(), AifRestMethod::Get);
        let dynamic = AifEncodedScopeElement::new(
            "dynamic".to_string(),
            make_bitflags!(AifRestMethod::{DynamicGet | DynamicFetch}),
        );
        let all = AifEncodedScopeElement::new("all".to_string(), BitFlags::all());
        let none = AifEncodedScopeElement::new("none".to_string(), BitFlags::empty());
        (restricted, dynamic, all, none)
    }

    #[test]
    fn test_aif_rest_method_serialize() {
        for method in AifRestMethodSet::all() {
            let mut serialized = Vec::<u8>::new();
            assert!(into_writer(&method, &mut serialized).is_ok());
            assert_eq!(
                method,
                from_reader::<AifRestMethod, &[u8]>(serialized.as_slice())
                    .expect("couldn't deserialize")
            );
        }
    }

    #[test]
    fn test_scope_elements_normal() {
        let (restricted, dynamic, all, none) = example_elements();
        let single = AifEncodedScope::new(vec![restricted.clone()]);
        assert_eq!(single.elements(), &vec![restricted]);

        let multiple = AifEncodedScope::new(vec![dynamic.clone(), all.clone()]);
        assert_eq!(multiple.elements(), &vec![dynamic.clone(), all.clone()]);

        let single_arr = AifEncodedScope::from(vec![("none".to_string(), BitFlags::empty())]);
        assert_eq!(single_arr.elements(), &vec![none]);

        let multi_arr = AifEncodedScope::from(vec![
            (
                "dynamic".to_string(),
                make_bitflags!(AifRestMethod::{DynamicGet | DynamicFetch}),
            ),
            ("all".to_string(), BitFlags::all()),
        ]);
        assert_eq!(multi_arr.to_elements(), vec![dynamic, all]);
    }

    #[test]
    fn test_scope_elements_valid() -> Result<(), InvalidAifEncodedScopeError> {
        let (restricted, dynamic, all, none) = example_elements();
        let multi = AifEncodedScope::try_from(vec![
            ("restricted".to_string(), u64::pow(2, 0)),
            ("all".to_string(), BitFlags::<AifRestMethod>::all().bits()),
            ("none".to_string(), 0),
        ])?;
        assert_eq!(multi.to_elements(), vec![restricted, all, none]);

        let single = AifEncodedScope::try_from(vec![(
            "dynamic".to_string(),
            u64::pow(2, 32) + u64::pow(2, 36),
        )])?;
        assert_eq!(single.to_elements(), vec![dynamic]);
        Ok(())
    }

    #[test]
    fn test_scope_elements_invalid() {
        // String part can't be invalid, so we ignore it here
        let invalids = vec![
            u64::pow(2, 7),
            u64::pow(2, 31),
            u64::pow(2, 39),
            u64::pow(2, 63),
            0xFFFF_FFFF_FFFF_FFFF, // maximum
        ];
        for invalid in invalids {
            assert!(
                !AifEncodedScope::try_from(vec![("whatever".to_string(), invalid)])
                    .expect_err("must be error")
                    .to_string()
                    .is_empty()
            );
        }
    }

    #[test]
    fn test_scope_elements_empty() -> Result<(), String> {
        // Note: Spec doesn't seem to mention anything about emptiness, so we assume it's allowed.
        assert!(AifEncodedScope::try_from(Vec::<(String, u64)>::new()).is_ok());
        let empty = AifEncodedScope::from(Vec::<(String, BitFlags<AifRestMethod>)>::new());
        assert_eq!(empty.elements(), &vec![]);
        let mut serialized = Vec::<u8>::new();
        into_writer(&empty, &mut serialized).map_err(|x| x.to_string())?;
        assert_eq!(&serialized, &Vec::from([0x80]));
        assert_eq!(
            from_reader::<Scope, &[u8]>(serialized.as_slice()).map_err(|x| x.to_string())?,
            Scope::from(empty)
        );
        Ok(())
    }

    #[test]
    fn test_scope_encoding() -> Result<(), String> {
        // This tests the encoding of the scope using the example given in Figure 5 of the AIF RFC.
        let cbor = hex::decode("8382672F732F74656D700182662F612F6C65640582652F64746C7302")
            .map_err(|x| x.to_string())?;
        let expected: Scope = AifEncodedScope::from(vec![
            ("/s/temp", make_bitflags!(AifRestMethod::{Get})),
            ("/a/led", make_bitflags!(AifRestMethod::{Put | Get})),
            ("/dtls", make_bitflags!(AifRestMethod::{Post})),
        ])
        .into();
        assert_eq!(
            expected,
            from_reader::<Scope, &[u8]>(cbor.as_slice()).map_err(|x| x.to_string())?
        );
        Ok(())
    }

    #[test]
    fn test_scope_invalid_try_from() {
        let scope = Scope::from(LibdcafEncodedScope::new("empty", AifRestMethodSet::empty()));
        let error = AifEncodedScope::try_from(scope).expect_err("expected error");
        assert_eq!(error.actual_type, "LibdcafEncoded");
        assert_eq!(error.expected_type, "AifEncoded");
        assert_eq!(error.general_type, PhantomData::<Scope>::default());
    }
}

mod libdcaf {
    use core::marker::PhantomData;

    use ciborium::de::from_reader;

    #[cfg(not(feature = "std"))]
    use {alloc::string::ToString, alloc::vec};

    use crate::error::{InvalidAifEncodedScopeError, ScopeFromValueError};
    use crate::{LibdcafEncodedScope, Scope};

    use super::aif::example_elements;

    #[test]
    fn test_scope_elements_normal() {
        let (restricted, dynamic, all, none) = example_elements();

        for element in vec![restricted, dynamic, all, none] {
            let scope = LibdcafEncodedScope::from_element(element.clone());
            assert_eq!(scope.elements(), vec![&element]);
        }
    }

    #[test]
    fn test_scope_element_valid() -> Result<(), InvalidAifEncodedScopeError> {
        let (restricted, _, _, _) = example_elements();
        let scope = LibdcafEncodedScope::try_from_bits("restricted".to_string(), u64::pow(2, 0))?;
        assert_eq!(scope.to_elements(), vec![restricted]);
        Ok(())
    }

    #[test]
    fn test_scope_element_invalid() {
        // String part can't be invalid, so we ignore it here
        let invalids = vec![
            u64::pow(2, 7),
            u64::pow(2, 31),
            u64::pow(2, 39),
            u64::pow(2, 63),
            0xFFFF_FFFF_FFFF_FFFF, // maximum
        ];
        for invalid in invalids {
            assert!(
                !LibdcafEncodedScope::try_from_bits("whatever".to_string(), invalid)
                    .expect_err("must be error")
                    .to_string()
                    .is_empty()
            );
        }
    }

    #[test]
    fn test_scope_element_empty() {
        // Emptiness isn't allowed here.
        let serialized = vec![0x80]; // empty CBOR array
                                     // That means that this *must not* resolve to a libdcaf scope
        assert!(from_reader::<Scope, &[u8]>(serialized.as_slice())
            .ok()
            .map(LibdcafEncodedScope::try_from)
            .and_then(Result::ok)
            .is_none());
    }

    #[test]
    fn test_scope_invalid_try_from() -> Result<(), ScopeFromValueError> {
        let scope = Scope::try_from(vec![0xDC, 0xAF].as_slice())?;
        let error = LibdcafEncodedScope::try_from(scope).expect_err("expected error");
        assert_eq!(error.actual_type, "BinaryEncoded");
        assert_eq!(error.expected_type, "LibdcafEncoded");
        assert_eq!(error.general_type, PhantomData::<Scope>::default());
        Ok(())
    }
}

/// Tests for binary encoded scopes.
mod binary {
    #[cfg(not(feature = "std"))]
    use alloc::{boxed::Box, string::ToString, vec};
    use core::marker::PhantomData;

    use ciborium::value::{Integer, Value};

    use crate::common::scope::BinaryEncodedScope;
    use crate::error::{InvalidBinaryEncodedScopeError, ScopeFromValueError};
    use crate::Scope;

    #[test]
    fn test_scope_elements_normal() -> Result<(), InvalidBinaryEncodedScopeError> {
        let single = BinaryEncodedScope::try_from(vec![0].as_slice())?;
        assert!(single.elements(Some(0x20))?.eq(&vec![vec![0]]));

        let simple1 = BinaryEncodedScope::try_from(vec![0, 1, 2].as_slice())?;
        assert!(simple1.elements(Some(0x20))?.eq(&vec![vec![0, 1, 2]]));
        assert!(simple1.elements(Some(1))?.eq(&vec![vec![0], vec![2]]));

        let simple2 = BinaryEncodedScope::try_from(vec![0xDC, 0x20, 0xAF].as_slice())?;
        assert!(simple2
            .elements(Some(0x20))?
            .eq(&vec![vec![0xDC], vec![0xAF]]));
        assert!(simple2.elements(Some(0))?.eq(&vec![vec![0xDC, 0x20, 0xAF]]));

        let simple3 = BinaryEncodedScope::try_from(
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0xDC, 0xAF, 0, 1].as_slice(),
        )?;
        assert!(simple3.elements(Some(0))?.eq(&vec![
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            vec![0xDC, 0xAF],
            vec![1],
        ]));
        assert!(simple3
            .elements(Some(0xEF))?
            .eq(&vec![vec![0xDE, 0xAD, 0xBE], vec![0, 0xDC, 0xAF, 0, 1]]));
        assert!(simple3
            .elements(Some(2))?
            .eq(&vec![vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0xDC, 0xAF, 0, 1]]));
        Ok(())
    }

    #[test]
    fn test_scope_elements_empty() -> Result<(), InvalidBinaryEncodedScopeError> {
        assert!(BinaryEncodedScope::try_from(vec![].as_slice()).is_err());
        // Assuming 0 is separator
        let empty_vecs = vec![vec![0], vec![0, 0], vec![0, 0, 0]];
        for vec in empty_vecs {
            assert!(!BinaryEncodedScope::try_from(vec.as_slice())?
                .elements(Some(0))
                .expect_err("must be error")
                .to_string()
                .is_empty());
            // If the separator is something else, the result should just contain the vec
            // as a single element.
            assert!(BinaryEncodedScope::try_from(vec.as_slice())?
                .elements(Some(1))?
                .eq(&vec![vec]));
        }
        Ok(())
    }

    #[test]
    fn test_scope_elements_invalid_separators() -> Result<(), InvalidBinaryEncodedScopeError> {
        // Assuming 0 is separator
        let invalid = vec![
            vec![0xDC, 0xAF, 0],
            vec![0xDC, 0xAF, 0, 0],
            vec![0, 0xDC, 0xAF],
            vec![0, 0, 0xDC, 0xAF],
            vec![0, 0xDC, 0xAF, 0],
            vec![0, 0, 0xDC, 0xAF, 0, 0],
            vec![0, 0, 0xDC, 0xAF, 0, 0],
            vec![0xDC, 0, 0, 0xAF],
            vec![0, 0xDC, 0, 0xAF, 0],
            vec![0, 0, 0xDC, 0, 0xAF, 0],
            vec![0, 0xDC, 0, 0, 0xAF, 0],
            vec![0, 0xDC, 0, 0xAF, 0, 0],
            vec![0, 0, 0xDC, 0, 0, 0xAF, 0, 0],
        ];
        for vec in invalid {
            assert!(!BinaryEncodedScope::try_from(vec.as_slice())?
                .elements(Some(0))
                .expect_err("must be error")
                .to_string()
                .is_empty());
            // If the separator is something else, the result should just contain the vec
            // as a single element.
            assert!(BinaryEncodedScope::try_from(vec.as_slice())?
                .elements(Some(1))?
                .eq(&vec![vec]));
        }
        Ok(())
    }

    #[test]
    fn test_scope_value() -> Result<(), ScopeFromValueError> {
        let scope = Scope::try_from(vec![0xDC, 0xAF].as_slice())?;
        let value = Value::from(scope.clone());
        assert!(value.is_bytes());
        assert_eq!(
            value.as_bytes().expect("not bytes"),
            vec![0xDC, 0xAF].as_slice()
        );
        assert_eq!(Scope::try_from(value)?, scope);
        Ok(())
    }

    #[test]
    fn test_scope_invalid_try_from() -> Result<(), ScopeFromValueError> {
        let scope = Scope::try_from(vec!["first", "second"])?;
        let error = BinaryEncodedScope::try_from(scope).expect_err("expected error");
        assert_eq!(error.actual_type, "TextEncoded");
        assert_eq!(error.expected_type, "BinaryEncoded");
        assert_eq!(error.general_type, PhantomData::<Scope>::default());

        let invalid_values = vec![
            Value::Bool(true),
            Value::Integer(Integer::from(u8::MIN)),
            Value::Float(0.5),
            Value::Null,
            Value::Tag(0, Box::new(Value::Null)),
            Value::Map(vec![]),
        ];
        for value in invalid_values {
            assert!(!Scope::try_from(value)
                .expect_err("must be error")
                .to_string()
                .is_empty());
        }
        Ok(())
    }
}
