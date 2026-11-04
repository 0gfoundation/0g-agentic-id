fn main() -> std::io::Result<()> {
    tonic_build::compile_protos("proto/tapp_service.proto")?;

    // RPC bindings need only the ABI. The full Foundry artifact contains
    // unresolved linked-library bytecode that Alloy cannot deserialize.
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let artifact = manifest.join("../../../contracts/out/AgenticID.sol/AgenticID.json");
    println!("cargo:rerun-if-changed={}", artifact.display());
    let artifact: serde_json::Value = serde_json::from_slice(&std::fs::read(artifact)?)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let abi = artifact
        .get("abi")
        .filter(|value| value.is_array())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AgenticID artifact has no ABI array",
            )
        })?;
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("AgenticID.abi.json"), serde_json::to_vec(abi)?)
}
