use pest::Parser;

#[derive(Parser)]
#[grammar = "pem.pest"]
struct PemParser;
