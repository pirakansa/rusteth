use cli_template::greet;

#[test]
fn it_runs_basic_logic() {
    assert_eq!(greet(None), "Hello, world!");
}
