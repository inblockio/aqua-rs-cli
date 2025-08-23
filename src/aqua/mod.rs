pub mod delete_revision_from_aqua_chain;
pub mod generate_aqua_chain_from_file;
pub mod sign;
pub mod verify;
pub mod wallet;
pub mod witness;

// New v3 modules
pub mod content;
pub mod form;
pub mod link;

// Re-export commonly used functions for convenience
pub use content::cli_generate_content_revision;
pub use delete_revision_from_aqua_chain::cli_remove_revisions_from_aqua_chain;
pub use form::cli_generate_form_revision;
pub use generate_aqua_chain_from_file::cli_generate_aqua_chain;
pub use link::cli_generate_link_revision;
pub use sign::cli_sign_chain;
pub use verify::cli_verify_chain;
pub use witness::cli_witness_chain;
