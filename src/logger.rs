use env_logger::{Builder, Env, Target};
use std::fs::OpenOptions;


pub fn init_logger(path: &str) {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("can not open the log file");

    Builder::from_env(Env::default().default_filter_or("info"))
        .target(Target::Pipe(Box::new(file)))
        .init();
}