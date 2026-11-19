// SPDX-License-Identifier: Apache-2.0
//! Offline CLI for public conformance vectors only; never pass credentials.

use std::env;
use std::fmt::Write as _;
use std::process;
use szl_receipt_wire::{pae, MAX_PAYLOAD_BYTES};

fn from_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    if input.len() > MAX_PAYLOAD_BYTES * 2 {
        return Err("payload exceeds local limit");
    }
    if input.len() % 2 != 0 {
        return Err("hex input has odd length");
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| "non-ASCII hex input")?;
        out.push(u8::from_str_radix(text, 16).map_err(|_| "invalid hex input")?);
    }
    Ok(out)
}

fn to_hex(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        write!(out, "{byte:02x}").expect("String write cannot fail");
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || args[1] != "pae-hex" {
        eprintln!("usage: szl-receipt-wire-cli pae-hex <public-type> <public-payload-hex>");
        process::exit(2);
    }
    let result =
        from_hex(&args[3]).and_then(|body| pae(&args[2], &body).map_err(|_| "PAE input rejected"));
    match result {
        Ok(bytes) => println!("{}", to_hex(&bytes)),
        Err(error) => {
            eprintln!("{error}");
            process::exit(2);
        }
    }
}
