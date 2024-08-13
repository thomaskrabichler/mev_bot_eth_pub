use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn log_to_file(data: &str) {
    let path = Path::new("src/data");
    create_dir_all(path).expect("Failed to create data directory");

    let file_path = path.join("benchmarking_log_llamarpc.txt");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Failed to open log file");

    writeln!(file, "{}", data).expect("Failed to write to log file");
}
