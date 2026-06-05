fn main() {
    println!("Argus examples are organized as a six-step ladder:\n");
    println!("  1. cargo run -p argus-examples --bin schnorr");
    println!("     cargo run -p argus-examples --bin schnorr -- --live");
    println!("  2. cargo run -p argus-examples --bin dleq");
    println!("  3. cargo run -p argus-examples --bin preprocessed_lookup");
    println!("  4. cargo run -p argus-examples --bin preprocessed_sumcheck");
    println!("  5. cargo run -p argus-examples --bin composition");
    println!("  6. cargo run -p argus-examples --bin multiparty_threads");
    println!();
    println!("Advanced showcases are listed in crates/argus-examples/README.md.");
}
