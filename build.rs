use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

#[derive(serde::Deserialize)]
struct RdapBootstrap {
    services: Vec<RdapBootstrapEntry>,
}

#[derive(serde::Deserialize)]
struct RdapBootstrapEntry {
    #[serde(rename = "0")]
    tlds: Vec<String>,
    #[serde(rename = "1")]
    servers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    
    let out_dir = env::var("OUT_DIR")?;
    let dest_path = Path::new(&out_dir).join("rdap_mappings.rs");
    
    // Try to fetch latest IANA data, fallback to minimal set if it fails
    let mappings = match fetch_iana_mappings().await {
        Ok(mappings) => {
            println!("cargo:warning=✅ Fetched {} RDAP mappings from IANA", mappings.len());
            mappings
        }
        Err(e) => {
            println!("cargo:warning=⚠️ Failed to fetch IANA data ({}), using minimal fallback", e);
            get_minimal_fallback_mappings()
        }
    };
    
    // Generate the Rust code
    let mut code = String::new();
    code.push_str("// Auto-generated RDAP TLD mappings from IANA bootstrap data\n");
    code.push_str("// DO NOT EDIT - This file is generated at build time\n\n");
    code.push_str("pub static GENERATED_RDAP_SERVERS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {\n");
    code.push_str("    let mut map = HashMap::new();\n");
    
    for (tld, server) in &mappings {
        code.push_str(&format!("    map.insert(\"{}\", \"{}\");\n", tld, server));
    }
    
    code.push_str("    map\n");
    code.push_str("});\n");
    
    fs::write(dest_path, code)?;
    Ok(())
}

async fn fetch_iana_mappings() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
        
    let response = client
        .get("https://data.iana.org/rdap/dns.json")
        .send()
        .await?;
        
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }
    
    let bootstrap: RdapBootstrap = response.json().await?;
    let mut mappings = HashMap::new();
    
    // Extract mappings, including ALL TLDs for cybersecurity analysis
    for service in bootstrap.services {
        if let Some(server) = service.servers.first() {
            for tld in service.tlds {
                // Include EVERYTHING - cybersecurity tools need to handle any TLD
                mappings.insert(tld, server.clone());
            }
        }
    }
    
    Ok(mappings)
}

fn get_minimal_fallback_mappings() -> HashMap<String, String> {
    let mut map = HashMap::new();
    
    // Minimal set that we know work (verified manually)
    map.insert("com".to_string(), "https://rdap.verisign.com/com/v1/".to_string());
    map.insert("net".to_string(), "https://rdap.verisign.com/net/v1/".to_string());
    map.insert("org".to_string(), "https://rdap.publicinterestregistry.org/rdap/".to_string());
    map.insert("uk".to_string(), "https://rdap.nominet.uk/uk/".to_string());
    map.insert("fr".to_string(), "https://rdap.nic.fr/".to_string());
    map.insert("nl".to_string(), "https://rdap.sidn.nl/".to_string());
    
    map
} 