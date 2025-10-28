use std::fs::File;

fn main() {
    let _file = File::open("data/test_dict.mdx").expect("Failed to open the file!");
    println!("Successfully opened the MDX file.");
}