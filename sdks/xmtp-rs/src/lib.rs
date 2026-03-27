use alloy::signers::local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use anyhow::Error;
use prost::Message;

mod serializable;
use serializable::maybe_get_text;

use std::iter::Iterator;
use std::sync::Arc;
use std::{path::PathBuf, time::Duration};
use xmtp_api_d14n::protocol::XmtpQuery;
use xmtp_common::time::now_ns;
use xmtp_content_types::{ContentCodec, text::TextCodec};
use xmtp_cryptography::signature::IdentifierValidationError;
use xmtp_cryptography::signature::SignatureError;
use xmtp_db::NativeDb;
use xmtp_db::{
    EncryptedMessageStore, EncryptionKey, group_message::StoredGroupMessage,
};
use xmtp_id::associations::unverified::UnverifiedSignature;
use xmtp_id::associations::Identifier;
use xmtp_mls::XmtpApi;
use xmtp_mls::XmtpApiClient;
use xmtp_mls::context::XmtpMlsLocalContext;
use xmtp_mls::groups::send_message_opts::SendMessageOptsBuilder;
use xmtp_mls::{InboxOwner, identity::IdentityStrategy};

pub type MlsContext =
    Arc<XmtpMlsLocalContext<XmtpApiClient, xmtp_db::DefaultStore, xmtp_db::DefaultMlsStore>>;
type Client = xmtp_mls::client::Client<MlsContext>;
type RustMlsGroup = xmtp_mls::groups::MlsGroup<MlsContext>;

/// This is an abstraction which allows to choose between different wallet types.
enum Wallet {
    LocalWallet(PrivateKeySigner),
}

impl InboxOwner for Wallet {
    fn get_identifier(&self) -> Result<Identifier, IdentifierValidationError> {
        match self {
            Wallet::LocalWallet(w) => w.get_identifier(),
        }
    }

    fn sign(&self, text: &str) -> Result<UnverifiedSignature, SignatureError> {
        match self {
            Wallet::LocalWallet(w) => w.sign(text),
        }
    }
}

pub async fn create_client<C: XmtpApi + Clone + XmtpQuery + 'static>(
    db_path: Option<PathBuf>,
    account: IdentityStrategy,
    grpc: C,
) -> Result<
    xmtp_mls::client::Client<
        Arc<XmtpMlsLocalContext<C, xmtp_db::DefaultStore, xmtp_db::DefaultMlsStore>>,
    >,
    Error,
> {
    let msg_store = get_encrypted_store(&db_path).await?;
    let builder = xmtp_mls::Client::builder(account).store(msg_store);
    let builder = builder.api_clients(grpc.clone(), grpc);

    let client = builder
        .with_remote_verifier()?
        .default_mls_store()?
        .build()
        .await?;

    Ok(client)
}

pub async fn register<C>(
    db_path: Option<PathBuf>,
    maybe_seed_phrase: Option<String>,
    client: C,
) -> Result<(), Error>
where
    C: Clone + XmtpApi + XmtpQuery + 'static,
{
    let w: Wallet = if let Some(seed_phrase) = maybe_seed_phrase {
        Wallet::LocalWallet(
            MnemonicBuilder::<English>::default()
                .phrase(seed_phrase.as_str())
                .build()
                .unwrap(),
        )
    } else {
        Wallet::LocalWallet(PrivateKeySigner::random())
    };

    let nonce = 0;
    let ident = w.get_identifier()?;
    let inbox_id = ident.inbox_id(nonce)?;
    let client = create_client(
        db_path,
        IdentityStrategy::new(inbox_id, ident, nonce, None),
        client,
    )
    .await?;
    let mut signature_request = client.identity().signature_request().unwrap();
    let signature = w.sign(&signature_request.signature_text()).unwrap();
    signature_request
        .add_signature(signature, client.scw_verifier())
        .await
        .unwrap();

    if let Err(e) = client.register_identity(signature_request).await {
        return Err(e.into());
    };

    Ok(())
}

pub async fn get_group(client: &Client, group_id: Vec<u8>) -> Result<RustMlsGroup, Error> {
    client.sync_welcomes().await?;
    let group = client.group(&group_id)?;
    group
        .sync()
        .await?;

    Ok(group)
}

pub async fn send(group: RustMlsGroup, msg: String) -> Result<(), Error> {
    let mut buf = Vec::new();
    TextCodec::encode(msg.clone())
        .unwrap()
        .encode(&mut buf)
        .unwrap();
    group
        .send_message(
            buf.as_slice(),
            SendMessageOptsBuilder::default()
                .should_push(true)
                .build()?,
        )
        .await?;
    Ok(())
}

pub fn format_messages(
    messages: Vec<StoredGroupMessage>,
    my_account_address: String,
) -> Result<String, Error> {
    let mut output: Vec<String> = vec![];

    for msg in messages {
        let text = maybe_get_text(&msg);
        if text.is_none() {
            continue;
        }

        let sender = if msg.sender_inbox_id == my_account_address {
            "Me".to_string()
        } else {
            msg.sender_inbox_id
        };

        let msg_line = format!(
            "[{:>15} ] {}:   {}",
            pretty_delta(now_ns() as u64, msg.sent_at_ns as u64),
            sender,
            text.expect("already checked")
        );
        output.push(msg_line);
    }
    output.reverse();

    Ok(output.join("\n"))
}

pub async fn get_encrypted_store(
    db: &Option<PathBuf>,
) -> Result<EncryptedMessageStore<NativeDb>, Error> {
    let store = match db {
        Some(path) => {
            let s = path.as_path().to_string_lossy().to_string();
            let db = NativeDb::builder().persistent(s).build_unencrypted()?;
            EncryptedMessageStore::new(db)?
        }

        None => {
            let db = NativeDb::builder()
                .key(static_enc_key())
                .ephemeral()
                .build()?;
            EncryptedMessageStore::new(db)?
        }
    };

    Ok(store)
}

pub fn address_to_identity(addresses: &[impl AsRef<str>]) -> Vec<Identifier> {
    addresses
        .iter()
        .map(|addr| Identifier::eth(addr.as_ref()).expect("Eth address is invalid"))
        .collect()
}

fn pretty_delta(now: u64, then: u64) -> String {
    let f = timeago::Formatter::new();
    let diff = now.abs_diff(then);
    f.convert(Duration::from_nanos(diff))
}

fn static_enc_key() -> EncryptionKey {
    [2u8; 32].into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        
    }
}
