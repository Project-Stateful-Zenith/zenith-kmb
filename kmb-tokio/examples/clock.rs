use kmb_tokio::now;
use std::error::Error;
use std::time::{Duration, Instant};

async fn offset<S>(c: &mut kmb_tokio::Client<S>) -> Result<i64, Box<dyn Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let started = Instant::now();
    let before = now();
    let rtc = c.read_clock().await?;
    let half = i128::try_from(started.elapsed().as_millis() / 2)?;
    let pc = i128::from(before.0).saturating_add(half);
    Ok(i64::try_from(i128::from(rtc.time.0).saturating_sub(pc))?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args
        .next()
        .ok_or("usage: clock HOST:PORT [--address N] [--adjust]")?;
    let mut address = 1;
    let mut adjust = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--address" => address = args.next().ok_or("--address needs a value")?.parse()?,
            "--adjust" => adjust = true,
            _ => return Err(format!("unknown option {a}").into()),
        }
    }
    let mut c = kmb_tokio::connect(host.as_str(), address).await?;
    c.identify().await?;
    println!("meter minus PC: {} ms", offset(&mut c).await?);
    if adjust {
        let sent = c.adjust_clock().await?;
        println!("adjusted to {} ms after 2000 (acknowledged)", sent.0);
        tokio::time::sleep(Duration::from_millis(500)).await;
        println!("meter minus PC: {} ms", offset(&mut c).await?);
    }
    Ok(())
}
