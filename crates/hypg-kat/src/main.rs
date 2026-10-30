//! hypg-kat binary: prints frozen KAT vectors.

#![forbid(unsafe_code)]

use hypg_kat::{print_ds_kats, print_hash_kats, print_kats, print_symm_kats};

fn main() {
    print_kats();
    print_symm_kats();
    print_ds_kats();
    print_hash_kats();
}
