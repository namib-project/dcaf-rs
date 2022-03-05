#![allow(unused)]

macro_rules! test_ser_de {
    ($value:ident$(;$transform_value:expr)? => $hex:literal) => {{
        let mut result = Vec::new();
        into_writer(&$value, &mut result).map_err(|x| x.to_string())?;
        #[cfg(feature = "std")]
        println!(
            "Result: {:?}, Original: {:?}",
            hex::encode(&result),
            &$value
        );
        assert_eq!(result, hex::decode($hex).map_err(|x| x.to_string())?);
        let decoded = from_reader(&result[..]).map_err(|x| x.to_string());
        if let Ok(CborMap(decoded_value)) = decoded {
            $(let decoded_value = $transform_value(decoded_value);)?
            assert_eq!(*$value, decoded_value);
            Ok(())
        } else if let Err(e) = decoded {
            return Err(e);
        } else {
            return Err("Invalid value: Not a CBOR map!".to_string());
        }
    }};
}

pub(crate) use test_ser_de;
