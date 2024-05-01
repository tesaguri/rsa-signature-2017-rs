macro_rules! assert_eq_dataset {
    ($left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left, right) => {
                let mut left_c14n = Vec::new();
                sophia_c14n::rdfc10::normalize(left, &mut left_c14n).unwrap();
                let left_c14n = String::from_utf8_lossy(&left_c14n);
                let mut right_c14n = Vec::new();
                sophia_c14n::rdfc10::normalize(right, &mut right_c14n).unwrap();
                let right_c14n = String::from_utf8_lossy(&right_c14n);
                assert_eq!(left_c14n, right_c14n);
            }
        }
    };
}

use sophia_api::dataset::CollectibleDataset;
use sophia_api::parser::QuadParser;
use sophia_inmem::dataset::LightDataset;
use sophia_turtle::parser::nq::NQuadsParser;

pub fn parse_nq(input: &str) -> LightDataset {
    LightDataset::from_quad_source(NQuadsParser {}.parse(input.as_bytes())).unwrap()
}
