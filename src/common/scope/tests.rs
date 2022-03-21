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
    use crate::common::scope::TextEncodedScope;
    use crate::error::{InvalidTextEncodedScopeError};

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
            assert!(TextEncodedScope::try_from(input).is_err())
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
            assert!(TextEncodedScope::try_from(input).is_err())
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
            assert!(TextEncodedScope::try_from(input).is_err())
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
            assert!(TextEncodedScope::try_from(input).is_err())
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
            assert!(TextEncodedScope::try_from(input).is_err())
        }
    }
}

/// Tests for binary encoded scopes.
mod binary {
    use crate::common::scope::BinaryEncodedScope;
    use crate::error::InvalidBinaryEncodedScopeError;

    #[test]
    fn test_scope_elements_normal() -> Result<(), InvalidBinaryEncodedScopeError> {
        let single = BinaryEncodedScope::try_from(vec![0].as_slice())?;
        assert!(single.elements(0x20)?.eq(vec![vec![0]]));

        let simple1 = BinaryEncodedScope::try_from(vec![0, 1, 2].as_slice())?;
        assert!(simple1.elements(0x20)?.eq(vec![vec![0, 1, 2]]));
        assert!(simple1.elements(1)?.eq(vec![vec![0], vec![2]]));

        let simple2 = BinaryEncodedScope::try_from(vec![0xDC, 0x20, 0xAF].as_slice())?;
        assert!(simple2.elements(0x20)?.eq(vec![vec![0xDC], vec![0xAF]]));
        assert!(simple2.elements(0)?.eq(vec![vec![0xDC, 0x20, 0xAF]]));

        let simple3 = BinaryEncodedScope::try_from(vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0xDC, 0xAF, 0, 1].as_slice())?;
        assert!(simple3.elements(0)?.eq(vec![vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0xDC, 0xAF], vec![1]]));
        assert!(simple3.elements(0xEF)?.eq(vec![vec![0xDE, 0xAD, 0xBE], vec![0, 0xDC, 0xAF, 0, 1]]));
        assert!(simple3.elements(2)?.eq(vec![vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0xDC, 0xAF, 0, 1]]));
        Ok(())
    }

    #[test]
    fn test_scope_elements_empty() -> Result<(), InvalidBinaryEncodedScopeError> {
        assert!(BinaryEncodedScope::try_from(vec![].as_slice()).is_err());
        // Assuming 0 is separator
        let empty_vecs = vec![
            vec![0], vec![0, 0], vec![0, 0, 0],
        ];
        for vec in empty_vecs {
            assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(0).is_err());
            // If the separator is something else, the result should just contain the vec
            // as a single element.
            assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(1)?.eq(vec![vec]));
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
            assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(0).is_err());
            // If the separator is something else, the result should just contain the vec
            // as a single element.
            assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(1)?.eq(vec![vec]));
        }
        Ok(())
    }
}
