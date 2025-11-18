use rusteth::NetplanFormat;
use std::str::FromStr;

#[test]
fn it_parses_known_formats() {
    assert!(matches!(
        NetplanFormat::from_str("yaml"),
        Ok(NetplanFormat::Yaml)
    ));
    assert!(matches!(
        NetplanFormat::from_str("json"),
        Ok(NetplanFormat::Json)
    ));
}
