//! Ad-hoc verification for the RDAP-first library client, cache behavior,
//! and WHOIS referral following. Run: cargo run --example verify_fixes

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = whois_service::WhoisClient::new().await?;

    // 1. Library should be RDAP-first for domains
    let r = client.lookup("example.com").await?;
    println!(
        "domain lookup     -> server={} registrar={:?}",
        r.whois_server,
        r.parsed_data.as_ref().and_then(|p| p.registrar.clone())
    );
    assert!(r.whois_server.starts_with("RDAP:"), "expected RDAP-first");

    // 2. Second lookup should be a cache hit
    let r2 = client.lookup("example.com").await?;
    println!("repeat lookup     -> cached={}", r2.cached);
    assert!(r2.cached, "expected cache hit");

    // 3. IP outside the local RIR table (130/8, RIPE) via library
    let r3 = client.lookup("130.89.148.14").await?;
    println!("out-of-table IP   -> server={}", r3.whois_server);

    // 4. Raw WHOIS IP path must follow ARIN's ReferralServer to RIPE
    let config = Arc::new(whois_service::Config::load()?);
    let whois = whois_service::whois::WhoisService::new(config).await?;
    let r4 = whois.lookup_ip("130.89.148.14").await?;
    println!(
        "whois IP referral -> final_server={} org={:?}",
        r4.server,
        r4.parsed_data.as_ref().and_then(|p| p.registrar.clone())
    );
    assert_eq!(r4.server, "whois.ripe.net", "expected referral to RIPE");

    println!("all checks passed");
    Ok(())
}
