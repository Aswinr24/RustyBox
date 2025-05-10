// Export all modules
pub mod callgraph;
pub mod decompilation;
pub mod disassembly;
pub mod metadata;
pub mod binary_parsing;

// Re-export key functions for convenience
pub use callgraph::analyze_callgraph;
pub use decompilation::decompile_binary;
pub use disassembly::disassemble_binary;
pub use metadata::extract_metadata;
pub use binary_parsing::analyze_binary;


