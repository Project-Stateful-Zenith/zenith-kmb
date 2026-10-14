use kmb::Frame;
use std::error::Error;
use std::time::Instant;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn unhex(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let (pairs, odd) = digits.as_chunks::<2>();
    if !odd.is_empty() {
        return Err(format!("odd hex length: {s}").into());
    }
    pairs
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut it = std::env::args().skip(1);
    let host = it
        .next()
        .ok_or("usage: raw HOST:PORT [--address N] [--replies N] CMD:HEX ...")?;
    let mut address = 1;
    let mut replies = 1;
    let mut requests = Vec::new();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--address" => address = it.next().ok_or("--address needs a value")?.parse()?,
            "--replies" => replies = it.next().ok_or("--replies needs a value")?.parse()?,
            _ => {
                let (cmd, payload) = arg
                    .split_once(':')
                    .ok_or_else(|| format!("not CMD:HEX: {arg}"))?;
                requests.push((cmd.parse::<u8>()?, unhex(payload)?));
            }
        }
    }
    let mut client = kmb_tokio::connect(host.as_str(), address).await?;
    client.set_byte_timeout(std::time::Duration::from_secs(5));
    for (cmd, payload) in requests {
        let frame = Frame::new(address, cmd, payload);
        println!("> {}", hex(&frame.encode()?));
        let n = if cmd == 22 { replies } else { 1 };
        let started = Instant::now();
        match client.exchange(&frame, n).await {
            Ok(frames) => {
                for f in frames {
                    let bytes = f.encode()?;
                    println!(
                        "< {} bytes, cmd {}, {:?}",
                        bytes.len(),
                        f.command,
                        started.elapsed()
                    );
                    println!("  {}", hex(&bytes));
                }
            }
            Err(e) => println!("< error after {:?}: {e}", started.elapsed()),
        }
    }
    Ok(())
}
