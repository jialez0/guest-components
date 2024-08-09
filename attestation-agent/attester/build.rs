fn main() {
    println!("cargo:rustc-link-lib=python3.8");
    println!("cargo:rustc-link-search=native=/usr/lib");
}