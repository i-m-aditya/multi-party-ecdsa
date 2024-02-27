use std::ops::Add;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use curv::elliptic::curves::ECScalar;
use futures::{SinkExt, StreamExt, TryStreamExt};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::LocalSignature;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::verify;
use structopt::StructOpt;

use curv::arithmetic::Converter;
use curv::BigInt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};
use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

mod gg20_sm_client;
use gg20_sm_client::join_computation;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-signing")]
    room: String,
    #[structopt(short, long)]
    local_share: PathBuf,

    #[structopt(short, long, use_delimiter(true))]
    parties: Vec<u16>,
    #[structopt(short, long)]
    data_to_sign: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    // println!("CLI args: {:?}", args);
    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;

    println!("Data to sign: {}", args.data_to_sign);
    let number_of_parties = args.parties.len();

    let (i, incoming, outgoing) =
        join_computation(args.address.clone(), &format!("{}-offline", args.room))
            .await
            .context("join offline computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(i, args.parties, local_share)?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let (i, incoming, outgoing) = join_computation(args.address, &format!("{}-online", args.room))
        .await
        .context("join online computation")?;

    tokio::pin!(incoming);
    tokio::pin!(outgoing);
    let public_key = completed_offline_stage.public_key().clone();

    println!("**********\n********\n");
    println!("Public Key{:?}", public_key);

    println!("**********\n********\n");

    // To generate private key

    println!("Hello");
    let data = hex::decode(&args.data_to_sign)?;
    println!("Args in u8: \n{:?}", data);

    let (signing, partial_signature) = SignManual::new(
        // BigInt::from_bytes(args.data_to_sign.as_bytes()),
        BigInt::from_bytes(&data),
        completed_offline_stage,
    )?;

    outgoing
        .send(Msg {
            sender: i,
            receiver: None,
            body: partial_signature,
        })
        .await?;

    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;
    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;

    // signature.r.as_raw().serialize();
    let mut rs_vec = signature.r.as_raw().serialize().to_vec();
    let s_vec = signature.s.as_raw().serialize().to_vec();
    rs_vec.extend(s_vec);
    // let rs = format!("[{:?},{:?}]", signature.r.as_raw().serialize(), signature.s.as_raw().serialize());

    let _ = verify(
        &signature,
        &public_key,
        &BigInt::from_bytes(args.data_to_sign.as_bytes()),
    );
    let signature = serde_json::to_string(&signature).context("serialize signature")?;
    println!("Signature: \n{}", signature);
    println!("\n\nRS: {:?}\n", rs_vec);

    Ok(())
}
