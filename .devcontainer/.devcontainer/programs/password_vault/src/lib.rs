use anchor_lang::prelude::*;

declare_id!("GCA4aqiUT57vPoc6seLrSLBXk9BRnp3Ptpqb6nbg19JH");

#[program]
pub mod password_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, data: [u8; 109], data_len: u32, bump: u8) -> Result<()> {
        let account = &mut ctx.accounts.storage_account;
        require!(!account.is_initialized, ErrorCode::AlreadyInitialized);
        require!(data_len as usize <= 109, ErrorCode::DataTooLarge);

        account.is_initialized = true;
        let len = data_len as usize;
        account.data.fill(0);
        account.data[..len].copy_from_slice(&data[..len]);
        account.data_len = data_len;
        account.bump = bump;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut, seeds = [payer.key().as_ref(), b"password_vault"], bump)]
    pub storage_account: Account<'info, StorageAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct StorageAccount {
    pub is_initialized: bool,
    pub data: [u8; 1024],
    pub data_len: u32,
    pub bump: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Account already initialized")]
    AlreadyInitialized,
    #[msg("Data size exceeds maximum allowed")]
    DataTooLarge,
}
