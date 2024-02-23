use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use round_based::async_runtime::AsyncProtocol;

mod gg20_sm_client;
use gg20_sm_client::join_computation;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    room: String,
    #[structopt(short, long)]
    output: PathBuf,

    #[structopt(short, long)]
    index: u16,
    #[structopt(short, long)]
    threshold: u16,
    #[structopt(short, long)]
    number_of_parties: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();

    println!("CLI args: {:?}", args);
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)
        .await
        .context("cannot create output file")?;

    println!("args address {:?}", args.address);
    println!("args room {:?}", args.room);

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(args.index, args.threshold, args.number_of_parties)?;
    let output = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    // println!("Public key: {:?}", output.public_key());
    let point = output.public_key();

    println!("Point: \n {:?}", point);
    let pk = point.into_raw().ge.unwrap();
    let public_key = pk.0;

    // let mut hasher = Sha224::keccak256

    // println!("Public Key Compressed: ");
    // println!("{:x}", public_key);

    let uncompressed_public_key = public_key.serialize_uncompressed();
    println!("Uncompressed:\n{:?}", uncompressed_public_key);

    // let mut hasher = Keccak256::new();

    // hasher.update(&uncompressed_public_key[1..]);
    // let result = hasher.finalize();
    // let ethereum_addy = &result[12..32];
    // let ethereum_address = "0x".to_string() + hex::encode(ethereum_addy).as_str();

    // println!("Ethereum address: {}", ethereum_address);

    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;

    // println!("Output as slice{:?}", output.as_slice());
    tokio::io::copy(&mut output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;

    Ok(())
}
