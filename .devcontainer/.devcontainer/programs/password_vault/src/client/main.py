import asyncio
import base64
import json
import hashlib
import base58
from os import urandom
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.instruction import Instruction, AccountMeta, CompiledInstruction
from solders.message import MessageV0, MessageHeader
from solders.transaction import VersionedTransaction
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.rpc.responses import GetTransactionResp
from solana.rpc.async_api import AsyncClient
from solana.rpc.types import TxOpts
from cryptography.fernet import Fernet
from typing import Optional

DEVNET_URL = "http://localhost:8899"
PROGRAM_ID = Pubkey.from_string("GCA4aqiUT57vPoc6seLrSLBXk9BRnp3Ptpqb6nbg19JH")  # Updated Program ID
SYS_PROGRAM_ID = Pubkey.from_string("11111111111111111111111111111111")

def load_keypair(filename: str) -> Keypair:
    with open(filename, "r") as f:
        keypair_data = json.load(f)
    secret_key = base58.b58decode(keypair_data["secret_key"])
    return Keypair.from_bytes(secret_key)

def get_random_bytes(length: int) -> bytes:
    return urandom(length)

def encrypt_password(password: str, key: bytes) -> str:
    cipher = Fernet(base64.urlsafe_b64encode(key))
    return base64.b64encode(cipher.encrypt(password.encode('utf-8'))).decode('ascii')

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    cipher = Fernet(base64.urlsafe_b64encode(key))
    encrypted_bytes = base64.b64decode(encrypted_password.encode('ascii'))
    return cipher.decrypt(encrypted_bytes).decode('utf-8')

def save_encryption_key(key: bytes, filename: str):
    with open(filename, "wb") as f:
        f.write(key)
    print(f"🔑 Ключ шифрування збережено у {filename}")

async def get_minimum_balance_for_rent_exemption(client: AsyncClient, data_size: int) -> int:
    print("📏 Отримання мінімального балансу для ренти...")
    resp = await client.get_minimum_balance_for_rent_exemption(data_size, commitment="confirmed")
    return resp.value

async def request_airdrop_if_needed(client: AsyncClient, pubkey: Pubkey) -> bool:
    print("💰 Перевірка балансу...")
    balance = await client.get_balance(pubkey, commitment="confirmed")
    print(f"💰 Баланс: {balance.value / 1e9} SOL")
    if balance.value / 1e9 < 0.5:
        print("💧 Запит airdrop 1 SOL...")
        try:
            airdrop_sig = await client.request_airdrop(pubkey, 1_000_000_000)
            await client.confirm_transaction(airdrop_sig.value, commitment="confirmed")
            print("✅ Airdrop виконано!")
            return True
        except Exception as e:
            print(f"❌ Помилка airdrop: {str(e)}")
            return False
    print("✅ Баланс достатній, airdrop не потрібен")
    return True

async def store_encrypted_password(client: AsyncClient, payer: Keypair, storage_account_pubkey: Pubkey, encrypted_password: str, bump: int) -> bool:
    print("🗄️ Зберігання пароля в акаунті...")
    try:
        space = 8 + 1 + 4 + 1024 + 1
        lamports = await get_minimum_balance_for_rent_exemption(client, space)
        print(f"📊 Потрібно lamports: {lamports}")

        encrypted_bytes = base64.b64decode(encrypted_password.encode('ascii'))
        print(f"🔍 Перші 20 байт encrypted_bytes (hex): {encrypted_bytes[:20].hex()}")
        print(f"🔒 Розмір зашифрованого пароля: {len(encrypted_bytes)} байт")

        # Створюємо масив фіксованого розміру (109 байт) для data
        data = bytearray(109)
        data[0:100] = encrypted_bytes  # 100 байт для зашифрованого пароля
        data[100] = bump  # 1 байт для bump
        data[101:109] = bytes([0] * 8)  # Заповнюємо 8 байт нулів

        data_len = 101  # 100 байт encrypted_bytes + 1 байт bump

        # Формуємо instruction_data: data (109 байт) + data_len (4 байти) + bump (1 байт)
        instruction_data = bytes(data) + data_len.to_bytes(4, byteorder='little') + bytes([bump])
        print(f"🔍 Повний instruction_data (hex): {instruction_data.hex()}")  # Додане дебагування

        print(f"🔍 Довжина instruction_data: {len(instruction_data)} байт")
        print(f"🔍 Довжина encrypted_bytes: {len(encrypted_bytes)} байт")
        print(f"🔍 Bump: {bump}")
        print(f"🔍 data_len: {data_len}")

        accounts = [
            AccountMeta(pubkey=storage_account_pubkey, is_signer=False, is_writable=True),
            AccountMeta(pubkey=payer.pubkey(), is_signer=True, is_writable=True),
            AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
        ]

        initialize_ix = Instruction(
            program_id=PROGRAM_ID,
            accounts=accounts,
            data=instruction_data
        )

        compute_unit_limit_ix = set_compute_unit_limit(600_000)
        compute_unit_price_ix = set_compute_unit_price(0)

        async with asyncio.timeout(10):
            blockhash_resp = await client.get_latest_blockhash(commitment="confirmed")
            recent_blockhash = blockhash_resp.value.blockhash
            print(f"🔄 Використовується blockhash: {recent_blockhash}")

        account_keys = [
            payer.pubkey(),
            storage_account_pubkey,
            SYS_PROGRAM_ID,
            Pubkey.from_string("ComputeBudget111111111111111111111111111111"),
            PROGRAM_ID,
        ]

        message = MessageV0(
            header=MessageHeader(num_required_signatures=1, num_readonly_signed_accounts=0, num_readonly_unsigned_accounts=2),
            account_keys=account_keys,
            recent_blockhash=recent_blockhash,
            instructions=[
                CompiledInstruction(program_id_index=3, accounts=bytes([0]), data=compute_unit_limit_ix.data),
                CompiledInstruction(program_id_index=3, accounts=bytes([0]), data=compute_unit_price_ix.data),
                CompiledInstruction(program_id_index=4, accounts=bytes([1, 0, 2]), data=initialize_ix.data),
            ],
            address_table_lookups=[]
        )

        transaction = VersionedTransaction(message, [payer])

        send_opts = TxOpts(
            skip_preflight=False,
            preflight_commitment="confirmed",
            max_retries=3
        )

        print("📤 Відправка транзакції ініціалізації...")
        result = await client.send_transaction(transaction, opts=send_opts)
        tx_id = result.value
        print(f"📤 Транзакція відправлена з ID: {tx_id}")

        print("⏳ Очікування підтвердження транзакції...")
        async with asyncio.timeout(15):
            confirmation = await client.get_transaction(tx_id, commitment="confirmed")
            if isinstance(confirmation, GetTransactionResp) and confirmation.value is not None:
                if confirmation.value.transaction.meta is not None and confirmation.value.transaction.meta.err is None:
                    print("✅ Акаунт ініціалізовано та пароль збережено!")
                else:
                    print(f"❌ Помилка ініціалізації: {confirmation.value.transaction.meta.err}")
                    return False
            else:
                print("❌ Транзакція не підтверджена")
                return False

        return True
    except Exception as e:
        print(f"❌ Помилка зберігання пароля: {str(e)}")
        raise

async def retrieve_encrypted_password(client: AsyncClient, storage_account_pubkey: Pubkey) -> str:
    print("📥 Отримання пароля з акаунта...")
    try:
        account_info = await client.get_account_info(storage_account_pubkey, commitment="confirmed")
        if account_info.value is None:
            print("❌ Акаунт не існує")
            raise Exception("Account not found")

        data = account_info.value.data
        if len(data) < 8:
            print("❌ Недостатньо даних в акаунті")
            raise Exception("Invalid account data")

        encrypted_bytes = data[8:]
        encrypted = base64.b64encode(encrypted_bytes).decode('ascii')
        print("✅ Зашифрований пароль отримано!")
        return encrypted
    except Exception as e:
        print(f"❌ Помилка отримання пароля: {str(e)}")
        raise

async def main():
    print("🚀 Запуск програми...")
    client = AsyncClient(DEVNET_URL)
    try:
        print("🔑 Ініціалізація ключів...")
        payer = load_keypair("payer.json")
        seeds = [bytes(payer.pubkey()), b"password_vault"]
        storage_account_pubkey, bump = Pubkey.find_program_address(seeds, PROGRAM_ID)  # Use PROGRAM_ID
        print(f"🗄️ Storage account (PDA): {storage_account_pubkey}")
        print(f"🔑 Payer: {payer.pubkey()}")

        print("🌧️ Перевірка необхідності airdrop...")
        if not await request_airdrop_if_needed(client, payer.pubkey()):
            print("\nℹ️ Отримійте SOL вручну через https://solfaucet.com...")
            print(f"Введіть ваш публічний ключ: {payer.pubkey()}\n")
            print("❌ Програма зупинена через помилку airdrop")
            return

        print("🔐 Очікування введення пароля...")
        password = input("Введіть пароль: ")
        if not password:
            print("❌ Пароль не може бути порожнім")
            return

        encryption_key = get_random_bytes(32)
        encrypted = encrypt_password(password, encryption_key)
        print(f"🔒 Зашифрований пароль: {encrypted[:50]}...")
        save_encryption_key(encryption_key, "encryption_key.txt")

        if await store_encrypted_password(client, payer, storage_account_pubkey, encrypted, bump):
            print("💾 Пароль успішно збережено в акаунті!")

            retrieved_encrypted = await retrieve_encrypted_password(client, storage_account_pubkey)
            print(f"📥 Отриміано зашифрований пароль: {retrieved_encrypted[:50]}...")

            decrypted = decrypt_password(retrieved_encrypted, encryption_key)
            print(f"🔓 Оригінальний пароль: {password}")
            print(f"🔓 Розшифрований пароль: {decrypted}")
        else:
            print("❌ Не вдалося зберегти пароль")

    except Exception as e:
        print(f"🔥 Критична помилка: {str(e)}")
    finally:
        await client.close()
        print("🔌 З'єднання закрито")

if __name__ == "__main__":
    asyncio.run(main())
