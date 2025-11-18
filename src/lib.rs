pub fn greet(name: Option<&str>) -> String {
    let who = name.unwrap_or("world");
    format!("Hello, {}!", who)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_greets_world_by_default() {
        assert_eq!(greet(None), "Hello, world!");
    }

    #[test]
    fn it_greets_given_name() {
        assert_eq!(greet(Some("Rust")), "Hello, Rust!");
    }
}
