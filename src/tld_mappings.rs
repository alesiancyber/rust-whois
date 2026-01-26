use once_cell::sync::Lazy;
use std::collections::HashMap;

// Hardcoded TLD mappings for the most popular domains (covers ~80% of traffic)
// This provides instant lookups for common TLDs while falling back to dynamic discovery
pub static HARDCODED_TLD_SERVERS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    
    // Top generic TLDs (gTLDs) - covers ~75% of all domains
    map.insert("com", "whois.verisign-grs.com");
    map.insert("net", "whois.verisign-grs.com");
    map.insert("org", "whois.pir.org");
    map.insert("info", "whois.afilias.net");
    map.insert("biz", "whois.neulevel.biz");
    map.insert("name", "whois.nic.name");
    map.insert("pro", "whois.registrypro.pro");
    
    // Popular new gTLDs
    map.insert("xyz", "whois.nic.xyz");
    map.insert("top", "whois.nic.top");
    map.insert("shop", "whois.nic.shop");
    map.insert("online", "whois.nic.online");
    map.insert("store", "whois.nic.store");
    map.insert("site", "whois.nic.site");
    map.insert("app", "whois.nic.google");
    map.insert("dev", "whois.nic.google");
    map.insert("tech", "whois.nic.tech");
    map.insert("blog", "whois.nic.blog");
    map.insert("club", "whois.nic.club");
    map.insert("live", "whois.nic.live");
    map.insert("fun", "whois.nic.fun");
    map.insert("vip", "whois.nic.vip");
    map.insert("click", "whois.uniregistry.net");
    
    // Top country code TLDs (ccTLDs) - covers major markets
    map.insert("uk", "whois.nic.uk");
    map.insert("co.uk", "whois.nic.uk");
    map.insert("org.uk", "whois.nic.uk");
    map.insert("me.uk", "whois.nic.uk");
    map.insert("de", "whois.denic.de");
    map.insert("fr", "whois.afnic.fr");
    map.insert("it", "whois.nic.it");
    map.insert("es", "whois.nic.es");
    map.insert("nl", "whois.domain-registry.nl");
    map.insert("be", "whois.dns.be");
    map.insert("ch", "whois.nic.ch");
    map.insert("at", "whois.nic.at");
    map.insert("se", "whois.iis.se");
    map.insert("no", "whois.norid.no");
    map.insert("dk", "whois.dk-hostmaster.dk");
    map.insert("fi", "whois.fi");
    map.insert("pl", "whois.dns.pl");
    map.insert("cz", "whois.nic.cz");
    map.insert("sk", "whois.sk-nic.sk");
    map.insert("hu", "whois.nic.hu");
    map.insert("ro", "whois.rotld.ro");
    map.insert("bg", "whois.register.bg");
    map.insert("hr", "whois.dns.hr");
    map.insert("si", "whois.arnes.si");
    map.insert("lt", "whois.domreg.lt");
    map.insert("lv", "whois.nic.lv");
    map.insert("ee", "whois.tld.ee");
    
    // Major Asia-Pacific ccTLDs
    map.insert("jp", "whois.jprs.jp");
    map.insert("co.jp", "whois.jprs.jp");
    map.insert("kr", "whois.kr");
    map.insert("cn", "whois.cnnic.cn");
    map.insert("com.cn", "whois.cnnic.cn");
    map.insert("hk", "whois.hkirc.hk");
    map.insert("tw", "whois.twnic.net.tw");
    map.insert("sg", "whois.sgnic.sg");
    map.insert("my", "whois.mynic.my");
    map.insert("th", "whois.thnic.co.th");
    map.insert("id", "whois.id");
    map.insert("ph", "whois.dot.ph");
    map.insert("vn", "whois.vnnic.vn");
    map.insert("in", "whois.registry.in");
    map.insert("co.in", "whois.registry.in");
    map.insert("au", "whois.auda.org.au");
    map.insert("com.au", "whois.auda.org.au");
    map.insert("nz", "whois.srs.net.nz");
    map.insert("co.nz", "whois.srs.net.nz");
    
    // Americas ccTLDs
    map.insert("ca", "whois.cira.ca");
    map.insert("us", "whois.nic.us");
    map.insert("mx", "whois.mx");
    map.insert("br", "whois.registro.br");
    map.insert("com.br", "whois.registro.br");
    map.insert("ar", "whois.nic.ar");
    map.insert("cl", "whois.nic.cl");
    map.insert("co", "whois.nic.co");
    map.insert("pe", "kero.yachay.pe");
    map.insert("uy", "whois.nic.org.uy");
    map.insert("ve", "whois.nic.ve");
    
    // Russia and Eastern Europe
    map.insert("ru", "whois.tcinet.ru");
    map.insert("su", "whois.tcinet.ru");
    map.insert("ua", "whois.ua");
    map.insert("by", "whois.cctld.by");
    map.insert("kz", "whois.nic.kz");
    
    // Middle East and Africa
    map.insert("il", "whois.isoc.org.il");
    map.insert("tr", "whois.nic.tr");
    map.insert("ae", "whois.aeda.net.ae");
    map.insert("sa", "whois.nic.net.sa");
    map.insert("za", "whois.registry.net.za");
    map.insert("co.za", "whois.registry.net.za");
    map.insert("eg", "whois.ripe.net");
    
    map
}); 