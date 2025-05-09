// Export all modules
pub mod disassembly;
pub mod decompilation;
pub mod metadata;
pub mod callgraph;

// Re-export key functions for convenience
pub use disassembly::disassemble_binary;
pub use decompilation::decompile_binary;
pub use metadata::extract_metadata;
pub use callgraph::analyze_callgraph;