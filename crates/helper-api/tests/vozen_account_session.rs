use helper_api::is_trusted_vozen_account_identity;

#[test]
fn trusted_vozen_account_identity_requires_the_expected_application_and_guild_scope() {
    assert!(is_trusted_vozen_account_identity(
        "100000000000000004",
        "100000000000000004",
        &["identify".into(), "email".into(), "guilds".into()],
    ));
    assert!(!is_trusted_vozen_account_identity(
        "100000000000000004",
        "another-application",
        &["identify".into(), "guilds".into()],
    ));
    assert!(!is_trusted_vozen_account_identity(
        "100000000000000004",
        "100000000000000004",
        &["identify".into(), "email".into()],
    ));
}
