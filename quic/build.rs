use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        aix: { target_os = "aix" },
        linux: { target_os = "linux" },
        linux_all: { any(target_os = "linux", target_os = "android") },
        freebsd: { target_os = "freebsd" },
        netbsd: { target_os = "netbsd" },
        non_freebsd: { any(target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly") },
        bsd: { any(freebsd, non_freebsd) },
        solarish: { any(target_os = "illumos", target_os = "solaris") },
        apple: { target_vendor = "apple" },
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
        rustls: { any(feature = "rustls-ring", feature = "rustls-aws-lc-rs", feature = "rustls-aws-lc-rs-fips") },
    }
}
