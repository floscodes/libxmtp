#![recursion_limit = "256"]

use xmtp_cli::cli_client;

pub async fn send_push_message(
    group: cli_client::RustMlsGroup,
    msg: String
) -> Result<(), anyhow::Error> {
    
    cli_client::send(group, msg).await
        .map_err(|_|anyhow::anyhow!("Failed to send message"))?;
    Ok(())

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        
    }
}
