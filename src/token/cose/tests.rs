use rstest::rstest;
use std::path::PathBuf;

#[rstest]
fn cose_examples_ecdsa(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-0*.json")] test_path: PathBuf,
) {
}
