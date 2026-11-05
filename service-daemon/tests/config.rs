use aegis_service::config::Config;
#[test]
fn rejects_unbounded_or_remote_configuration() {
    for json in [r#"{"roots":["C:\\Users"],"interval_seconds":0,"workers":1}"#,
        r#"{"roots":["C:\\Users"],"interval_seconds":60,"workers":5}"#,
        r#"{"roots":["\\\\server\\share"],"interval_seconds":60,"workers":1}"#,
        r#"{"roots":["C:relative"],"interval_seconds":60,"workers":1}"#,
        r#"{"roots":["C:\\Users\\..\\Windows"],"interval_seconds":60,"workers":1}"#] {
        assert!(serde_json::from_str::<Config>(json).unwrap().validate().is_err());
    }
}
#[test]
fn accepts_bounded_local_configuration() {
    let config: Config = serde_json::from_str(r#"{"roots":["C:\\Users"],"interval_seconds":3600,"workers":4,"watch":true}"#).unwrap();
    assert!(config.validate().is_ok());
}
#[test]
fn rejects_unknown_fields() {
    assert!(serde_json::from_str::<Config>(r#"{"roots":[],"interval_seconds":60,"workers":1,"delete":true}"#).is_err());
}
