fn main() {
    if let Err(error) = run() {
        eprintln!("toolkit Windows GUI MCP server failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        return toolkit_windows_automation::run_mcp_stdio();
    }
    #[cfg(windows)]
    if args.len() == 2 && args[0] == "--experimental-http-config" {
        return toolkit_windows_automation::run_mcp_http(std::path::Path::new(&args[1]));
    }
    Err("usage: toolkit-windows-gui-mcp [--experimental-http-config <trusted absolute config.json>]".into())
}
