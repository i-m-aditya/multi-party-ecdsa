FROM rust:latest
WORKDIR /app
COPY . .
RUN cargo build --release --examples
CMD ["target/release/examples/gg20_sm_manager"]