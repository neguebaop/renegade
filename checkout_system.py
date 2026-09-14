import os, re, io, json, base64, asyncio, random, string, secrets, math
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

import aiohttp
import discord
from discord import app_commands
from PIL import Image, ImageDraw, ImageFont
from database import db, ensure_schema

MISTIC_BASE = "https://api.misticpay.com/api"
CI = os.getenv("MISTICPAY_CLIENT_ID", "").strip()
CS = os.getenv("MISTICPAY_CLIENT_SECRET", "").strip()
FERNET_KEY = os.getenv("MISTICPAY_FERNET_KEY", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
WEBHOOK_TOKEN = os.getenv("MISTICPAY_WEBHOOK_TOKEN", "").strip()
STORE_URL = os.getenv("STORE_URL", "https://discord.gg/rnX2vXK5Hn").strip()
TERMS_URL = os.getenv("TERMS_URL", STORE_URL).strip()

BOT = None
ADMIN_CHECK = None
LICENSE_ORDER_LOCKS = {}

# Permissão especial para geração MANUAL de keys.
# A geração automática após pagamento continua funcionando para clientes.
LOCKSENSI_OWNER_ID = 1014602631689273444
LOCKSENSI_KEY_STAFF_ROLE_IDS = {
    1543797472017780756,
    1484684790757064744,
}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def money(v):
    return f"R${float(v):.2f}".replace(".", ",")


def code(n=10):
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(n)
    )


def clean_doc(v):
    return re.sub(r"\D", "", v or "")


def valid_url(v):
    return bool(v and re.match(r"^https?://", str(v)))


def init_db():
    ensure_schema()
    ensure_coupon_schema()
    ensure_split_schema()
    ensure_affiliate_schema()
    ensure_feedback_schema()
    ensure_license_schema()


def ensure_feedback_schema():
    """Adiciona links configuráveis dos botões por servidor."""
    con = db()
    try:
        con._conn.execute(
            "ALTER TABLE guild_config ADD COLUMN IF NOT EXISTS feedback_url TEXT"
        )
        con._conn.execute(
            "ALTER TABLE guild_config ADD COLUMN IF NOT EXISTS store_url TEXT"
        )
        con.commit()
    finally:
        con.close()


def ensure_license_schema():
    """
    Sistema de keys próprio da Lock Sensi, salvo no PostgreSQL/Supabase.
    Sistema próprio de keys no PostgreSQL/Supabase.
    """
    con = db()
    try:
        # Benefícios por produto.
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS purchase_role_id BIGINT"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS license_enabled INTEGER DEFAULT 0"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS license_duration_days INTEGER DEFAULT 30"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS license_prefix TEXT DEFAULT 'LOCK'"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS license_hwid_required INTEGER DEFAULT 1"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS license_app_code TEXT"
        )

        # Uma compra aprovada pode gerar no máximo uma key.
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS generated_keys(
                id BIGSERIAL PRIMARY KEY,
                guild_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                product_id BIGINT NOT NULL,
                order_id BIGINT NOT NULL UNIQUE,
                license_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                expires_at TIMESTAMP NULL,
                hwid TEXT NULL,
                hwid_bound_at TIMESTAMP NULL,
                last_used_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        con._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_generated_keys_guild_user
            ON generated_keys(guild_id,user_id,created_at DESC)
            """
        )
        con._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_generated_keys_status_expiry
            ON generated_keys(status,expires_at)
            """
        )
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS license_auth_guard(
                hwid_hash TEXT NOT NULL,
                app_code TEXT NOT NULL,
                failures INTEGER NOT NULL DEFAULT 0,
                blocked_until TIMESTAMPTZ NULL,
                last_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY(hwid_hash,app_code)
            )
            """
        )
        con._conn.execute("ALTER TABLE generated_keys ENABLE ROW LEVEL SECURITY")
        con._conn.execute("ALTER TABLE license_auth_guard ENABLE ROW LEVEL SECURITY")
        con._conn.execute(
            "DROP FUNCTION IF EXISTS public.validate_locksensi_key(text,text)"
        )
        con._conn.execute(
            r"""
            CREATE OR REPLACE FUNCTION public.validate_locksensi_key(
                p_key TEXT, p_hwid TEXT, p_app_code TEXT
            )
            RETURNS JSONB
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = public
            AS $$
            DECLARE
                r RECORD; guard_row RECORD;
                clean_key TEXT := upper(trim(coalesce(p_key,'')));
                clean_hwid TEXT := upper(trim(coalesce(p_hwid,'')));
                clean_app TEXT := upper(trim(coalesce(p_app_code,'')));
                fail_reason TEXT := NULL; product_app TEXT := '';
                seconds_left INTEGER := 0;
            BEGIN
                IF clean_hwid='' THEN RETURN jsonb_build_object('ok',false,'reason','hwid_required'); END IF;
                IF clean_app='' THEN RETURN jsonb_build_object('ok',false,'reason','app_invalid'); END IF;
                UPDATE public.license_auth_guard SET failures=0,blocked_until=NULL,last_attempt=now()
                 WHERE hwid_hash=clean_hwid AND app_code=clean_app AND blocked_until IS NOT NULL AND blocked_until<=now();
                SELECT * INTO guard_row FROM public.license_auth_guard
                 WHERE hwid_hash=clean_hwid AND app_code=clean_app;
                IF FOUND AND guard_row.blocked_until IS NOT NULL AND guard_row.blocked_until>now() THEN
                    seconds_left:=greatest(1,ceil(extract(epoch FROM (guard_row.blocked_until-now())))::integer);
                    RETURN jsonb_build_object('ok',false,'reason','rate_limited','retry_after_seconds',seconds_left);
                END IF;
                IF clean_key='' THEN fail_reason:='key_invalid'; ELSE
                    SELECT g.id,g.guild_id,g.user_id,g.product_id,g.order_id,g.license_key,g.status,g.expires_at,g.hwid,
                           coalesce(p.license_hwid_required,1) AS hwid_required,coalesce(p.license_app_code,'') AS license_app_code,
                           p.local_id AS product_local_id,p.name AS product_name
                      INTO r FROM public.generated_keys g LEFT JOIN public.products p ON p.id=g.product_id
                     WHERE upper(g.license_key)=clean_key FOR UPDATE OF g;
                    IF NOT FOUND THEN fail_reason:='key_invalid'; ELSE
                        product_app:=upper(trim(coalesce(r.license_app_code,'')));
                        IF lower(coalesce(r.status,''))='revoked' THEN fail_reason:='key_revoked';
                        ELSIF r.expires_at IS NOT NULL AND r.expires_at<=now() THEN
                            UPDATE public.generated_keys SET status='expired',updated_at=now() WHERE id=r.id; fail_reason:='key_expired';
                        ELSIF lower(coalesce(r.status,'active'))<>'active' THEN fail_reason:='key_inactive';
                        ELSIF product_app<>'' AND product_app<>clean_app THEN fail_reason:='wrong_product';
                        ELSIF coalesce(r.hwid_required,1)=1 AND coalesce(trim(r.hwid),'')<>'' AND upper(trim(r.hwid))<>clean_hwid THEN fail_reason:='hwid_mismatch';
                        END IF;
                    END IF;
                END IF;
                IF fail_reason IS NOT NULL THEN
                    INSERT INTO public.license_auth_guard(hwid_hash,app_code,failures,blocked_until,last_attempt) VALUES(clean_hwid,clean_app,1,NULL,now())
                    ON CONFLICT(hwid_hash,app_code) DO UPDATE SET failures=public.license_auth_guard.failures+1,
                      blocked_until=CASE WHEN public.license_auth_guard.failures+1>=5 THEN now()+interval '10 minutes' ELSE public.license_auth_guard.blocked_until END,last_attempt=now();
                    RETURN jsonb_build_object('ok',false,'reason',fail_reason);
                END IF;
                IF coalesce(r.hwid_required,1)=1 AND coalesce(trim(r.hwid),'')='' THEN
                    UPDATE public.generated_keys SET hwid=clean_hwid,hwid_bound_at=now(),last_used_at=now(),updated_at=now() WHERE id=r.id;
                ELSE UPDATE public.generated_keys SET last_used_at=now(),updated_at=now() WHERE id=r.id; END IF;
                INSERT INTO public.license_auth_guard(hwid_hash,app_code,failures,blocked_until,last_attempt) VALUES(clean_hwid,clean_app,0,NULL,now())
                ON CONFLICT(hwid_hash,app_code) DO UPDATE SET failures=0,blocked_until=NULL,last_attempt=now();
                RETURN jsonb_build_object('ok',true,'reason','ok','expires_at',r.expires_at,'guild_id',r.guild_id,'product_id',r.product_id,
                  'product_local_id',r.product_local_id,'product_name',r.product_name,'app_code',product_app,'app_bound',(product_app<>''));
            END;
            $$
            """
        )
        con._conn.execute(
            "REVOKE ALL ON FUNCTION public.validate_locksensi_key(TEXT,TEXT,TEXT) FROM PUBLIC"
        )
        con._conn.execute(
            "GRANT EXECUTE ON FUNCTION public.validate_locksensi_key(TEXT,TEXT,TEXT) TO anon"
        )
        con._conn.execute(
            "GRANT EXECUTE ON FUNCTION public.validate_locksensi_key(TEXT,TEXT,TEXT) TO authenticated"
        )
        con._conn.execute("REVOKE ALL ON TABLE public.generated_keys FROM anon")
        con._conn.execute("REVOKE ALL ON TABLE public.license_auth_guard FROM anon")

        con.commit()
    finally:
        con.close()


def _row_value(row, name, default=None):
    if not row:
        return default
    try:
        return row[name]
    except Exception:
        try:
            return row.get(name, default)
        except Exception:
            return default


def get_product_benefits(product):
    role_id = _row_value(product, "purchase_role_id")
    enabled = int(_row_value(product, "license_enabled", 0) or 0) == 1
    days = int(_row_value(product, "license_duration_days", 30) or 0)
    prefix = str(_row_value(product, "license_prefix", "LOCK") or "LOCK").strip()
    hwid_required = int(_row_value(product, "license_hwid_required", 1) or 0) == 1
    app_code = str(_row_value(product, "license_app_code", "") or "").strip().upper()

    return {
        "role_id": int(role_id) if role_id else None,
        "license_enabled": enabled,
        # 0 = permanente
        "duration_days": max(0, min(36500, days)),
        "prefix": normalize_license_prefix(prefix),
        "hwid_required": hwid_required,
        "app_code": app_code[:80],
    }


def normalize_license_prefix(value):
    value = re.sub(r"[^A-Za-z0-9]", "", str(value or "LOCK")).upper()
    return (value or "LOCK")[:12]


def normalize_license_key(value):
    return str(value or "").strip().upper()


def _key_alphabet():
    # Remove caracteres fáceis de confundir visualmente.
    return "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def build_license_key(prefix="LOCK"):
    prefix = normalize_license_prefix(prefix)
    alphabet = _key_alphabet()
    parts = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(3)]
    return f"{prefix}-{'-'.join(parts)}"


def _parse_db_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(raw)
        except Exception:
            try:
                dt = datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_expiry(value):
    dt = _parse_db_datetime(value)
    if not dt:
        return "Permanente"
    return dt.strftime("%d/%m/%Y %H:%M UTC")


def effective_key_status(row):
    status = str(_row_value(row, "status", "active") or "active").lower()
    if status == "revoked":
        return "revoked"
    expires = _parse_db_datetime(_row_value(row, "expires_at"))
    if expires and expires <= datetime.now(timezone.utc):
        return "expired"
    return "active"


def get_generated_key_by_order(order_id):
    con = db()
    row = con.execute(
        "SELECT * FROM generated_keys WHERE order_id=?",
        (int(order_id),),
    ).fetchone()
    con.close()
    return row


def get_generated_key(license_key, guild_id=None):
    key = normalize_license_key(license_key)
    con = db()
    if guild_id is None:
        row = con.execute(
            "SELECT * FROM generated_keys WHERE license_key=?",
            (key,),
        ).fetchone()
    else:
        row = con.execute(
            "SELECT * FROM generated_keys WHERE license_key=? AND guild_id=?",
            (key, int(guild_id)),
        ).fetchone()
    con.close()
    return row


def _build_expiry_hours(duration_hours):
    hours = int(duration_hours or 0)
    if hours <= 0:
        return None
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def _build_expiry(duration_days):
    """Compatibilidade: produtos antigos continuam configurados em dias."""
    days = int(duration_days or 0)
    return _build_expiry_hours(days * 24)


def create_unique_license(prefix):
    # Banco também possui UNIQUE(license_key). A checagem reduz colisões antes do INSERT.
    for _ in range(30):
        candidate = build_license_key(prefix)
        if not get_generated_key(candidate):
            return candidate
    raise RuntimeError("Não consegui gerar uma key única. Tente novamente.")


async def get_or_create_order_license(order_id):
    """
    Uma compra = uma key.
    O asyncio.Lock evita corrida entre watcher, entrega e botão Gerar Key.
    """
    order_id = int(order_id)
    lock = LICENSE_ORDER_LOCKS.setdefault(order_id, asyncio.Lock())

    async with lock:
        existing = get_generated_key_by_order(order_id)
        if existing:
            return str(existing["license_key"]), False

        order = get_order(order_id)
        if not order:
            raise RuntimeError("Pedido não encontrado.")
        if str(order["status"]).lower() != "aprovado":
            raise RuntimeError("O pedido ainda não foi aprovado.")

        product = get_product(order["product_id"])
        if not product:
            raise RuntimeError("Produto do pedido não encontrado.")

        benefits = get_product_benefits(product)
        if not benefits["license_enabled"]:
            raise RuntimeError("Este produto não possui geração de key ativada.")

        license_key = create_unique_license(benefits["prefix"])
        expires_at = _build_expiry(benefits["duration_days"])

        con = db()
        try:
            con.execute(
                """
                INSERT INTO generated_keys(
                    guild_id,user_id,product_id,order_id,license_key,
                    status,expires_at,created_at,updated_at
                )
                VALUES(?,?,?,?,?,'active',?,?,?)
                ON CONFLICT(order_id) DO NOTHING
                """,
                (
                    int(order["guild_id"]),
                    int(order["user_id"]),
                    int(order["product_id"]),
                    order_id,
                    license_key,
                    expires_at,
                    now_iso(),
                    now_iso(),
                ),
            )
            con.commit()
            saved = con.execute(
                "SELECT * FROM generated_keys WHERE order_id=?",
                (order_id,),
            ).fetchone()
        finally:
            con.close()

        if not saved:
            raise RuntimeError("Não foi possível registrar a key no Supabase.")

        return str(saved["license_key"]), True


async def find_license_order_for_user(guild_id, user_id):
    """Compra aprovada mais recente de produto com key; prioriza a que ainda não gerou."""
    con = db()
    try:
        rows = con.execute(
            """
            SELECT
                o.id,o.guild_id,o.user_id,o.product_id,o.product_name,o.status
            FROM orders o
            JOIN products p ON p.id=o.product_id
            WHERE o.guild_id=?
              AND o.user_id=?
              AND o.status='aprovado'
              AND COALESCE(p.license_enabled,0)=1
            ORDER BY o.id DESC
            LIMIT 50
            """,
            (int(guild_id), int(user_id)),
        ).fetchall()

        if not rows:
            return None

        for row in rows:
            issued = con.execute(
                "SELECT id FROM generated_keys WHERE order_id=?",
                (int(row["id"]),),
            ).fetchone()
            if not issued:
                return row

        return rows[0]
    finally:
        con.close()


def validate_locksensi_license(license_key, hwid=None, bind_hwid=True):
    """
    Função pronta para o painel/app Lock Sensi validar keys futuramente.

    Retorno:
      {"ok": True, ...}  ou  {"ok": False, "reason": "..."}
    """
    key = normalize_license_key(license_key)
    row = get_generated_key(key)
    if not row:
        return {"ok": False, "reason": "key_invalid"}

    status = effective_key_status(row)
    if status == "revoked":
        return {"ok": False, "reason": "key_revoked"}
    if status == "expired":
        con = db()
        try:
            con.execute(
                "UPDATE generated_keys SET status='expired',updated_at=? WHERE id=?",
                (now_iso(), int(row["id"])),
            )
            con.commit()
        finally:
            con.close()
        return {"ok": False, "reason": "key_expired"}

    product = get_product(row["product_id"])
    benefits = get_product_benefits(product)

    stored_hwid = str(_row_value(row, "hwid", "") or "").strip()
    supplied_hwid = str(hwid or "").strip()

    if benefits["hwid_required"]:
        if not supplied_hwid:
            return {"ok": False, "reason": "hwid_required"}

        if stored_hwid and stored_hwid != supplied_hwid:
            return {"ok": False, "reason": "hwid_mismatch"}

        if not stored_hwid and bind_hwid:
            con = db()
            try:
                con.execute(
                    """
                    UPDATE generated_keys
                    SET hwid=?,hwid_bound_at=?,last_used_at=?,updated_at=?
                    WHERE id=?
                    """,
                    (
                        supplied_hwid,
                        now_iso(),
                        now_iso(),
                        now_iso(),
                        int(row["id"]),
                    ),
                )
                con.commit()
            finally:
                con.close()
            stored_hwid = supplied_hwid
    else:
        con = db()
        try:
            con.execute(
                "UPDATE generated_keys SET last_used_at=?,updated_at=? WHERE id=?",
                (now_iso(), now_iso(), int(row["id"])),
            )
            con.commit()
        finally:
            con.close()

    return {
        "ok": True,
        "key": key,
        "guild_id": int(row["guild_id"]),
        "user_id": int(row["user_id"]),
        "product_id": int(row["product_id"]),
        "order_id": int(row["order_id"]),
        "expires_at": _row_value(row, "expires_at"),
        "expires_text": _format_expiry(_row_value(row, "expires_at")),
        "hwid_required": benefits["hwid_required"],
        "hwid": stored_hwid or None,
    }


async def grant_purchase_role(guild, member, product):
    """Entrega o cargo configurado no produto sem quebrar a entrega se der erro."""
    benefits = get_product_benefits(product)
    role_id = benefits["role_id"]

    if not role_id or not guild or not isinstance(member, discord.Member):
        return None

    role = guild.get_role(int(role_id))
    if not role:
        return f"Cargo configurado `{role_id}` não existe mais."

    if role in member.roles:
        return f"Cargo **{role.name}** já estava no usuário."

    try:
        await member.add_roles(
            role,
            reason=f"Compra aprovada: {product['name']}",
        )
        return f"Cargo **{role.name}** entregue."
    except discord.Forbidden:
        return (
            f"Não consegui entregar **{role.name}**. "
            "Coloque o cargo do bot acima dele e dê a permissão Gerenciar cargos."
        )
    except Exception as exc:
        return f"Erro ao entregar **{role.name}**: {str(exc)[:180]}"


def ensure_coupon_schema():
    """Cria/migra o sistema de cupons diretamente no PostgreSQL/Supabase."""
    con = db()
    try:
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS coupons(
                id BIGSERIAL PRIMARY KEY,
                guild_id BIGINT NOT NULL,
                code TEXT NOT NULL,
                discount_percent NUMERIC(5,2) NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, code)
            )
            """
        )
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cart_coupons(
                channel_id BIGINT PRIMARY KEY,
                guild_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                product_id BIGINT NOT NULL,
                coupon_code TEXT NOT NULL,
                discount_percent NUMERIC(5,2) NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS original_amount NUMERIC(12,2)"
        )
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code TEXT"
        )
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_percent NUMERIC(5,2)"
        )
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS discount_amount NUMERIC(12,2)"
        )

        # Cupom pode ser exclusivo de UM produto e possuir limite de utilizações.
        con._conn.execute(
            "ALTER TABLE coupons ADD COLUMN IF NOT EXISTS product_id BIGINT"
        )
        con._conn.execute(
            "ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_uses INTEGER"
        )
        con._conn.execute(
            "ALTER TABLE coupons ADD COLUMN IF NOT EXISTS used_count INTEGER NOT NULL DEFAULT 0"
        )
        con._conn.execute(
            "ALTER TABLE coupons ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP"
        )
        con._conn.execute("UPDATE coupons SET used_count=0 WHERE used_count IS NULL")
        con.commit()
    finally:
        con.close()


def ensure_split_schema():
    """Cria/migra os campos de split por produto no PostgreSQL/Supabase."""
    con = db()
    try:
        # Configuração fica NO PRODUTO. Produtos sem split continuam 100%
        # na MisticPay conectada ao servidor.
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS split_enabled INTEGER DEFAULT 0"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS split_user TEXT"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS split_tax NUMERIC(5,2) DEFAULT 0"
        )
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS split_override INTEGER DEFAULT 0"
        )
        # Splits individuais existentes continuam tendo prioridade.
        con._conn.execute(
            """
            UPDATE products
            SET split_override=1
            WHERE COALESCE(split_enabled,0)=1
              AND COALESCE(split_override,0)=0
            """
        )
        # Regra por nome-base: cobre todas as opções/variações do mesmo painel.
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS split_group_rules(
                id BIGSERIAL PRIMARY KEY,
                guild_id BIGINT NOT NULL,
                match_text TEXT NOT NULL,
                split_user TEXT NOT NULL,
                split_tax NUMERIC(5,2) NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                UNIQUE(guild_id, match_text)
            )
            """
        )
        # V4: regra vinculada ao PAINEL de vendas, e não ao texto do produto.
        # As colunas são opcionais para preservar regras antigas por nome-base.
        con._conn.execute(
            "ALTER TABLE split_group_rules ADD COLUMN IF NOT EXISTS panel_id BIGINT"
        )
        con._conn.execute(
            "ALTER TABLE split_group_rules ADD COLUMN IF NOT EXISTS panel_name TEXT"
        )
        con._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_split_group_rules_panel
            ON split_group_rules(guild_id, panel_id)
            WHERE panel_id IS NOT NULL
            """
        )

        # ID VISÍVEL/LOCAL por servidor.
        # O products.id continua sendo a chave global interna do banco, mas os
        # comandos administrativos usam local_id, que começa em 1 para cada guild.
        con._conn.execute(
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS local_id INTEGER"
        )

        # Preenche IDs locais para produtos antigos, separadamente por servidor.
        # Se o script já tiver sido executado antes, continua depois do maior ID local.
        con._conn.execute(
            """
            WITH maxes AS (
                SELECT guild_id, COALESCE(MAX(local_id), 0) AS max_local
                FROM products
                GROUP BY guild_id
            ),
            numbered AS (
                SELECT p.id,
                       COALESCE(m.max_local, 0)
                       + ROW_NUMBER() OVER (
                           PARTITION BY p.guild_id
                           ORDER BY p.id
                       ) AS new_local_id
                FROM products p
                LEFT JOIN maxes m ON m.guild_id = p.guild_id
                WHERE p.local_id IS NULL
            )
            UPDATE products p
            SET local_id = numbered.new_local_id
            FROM numbered
            WHERE p.id = numbered.id
            """
        )

        # Garante que o mesmo servidor não tenha dois produtos com o mesmo ID local.
        con._conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS uq_products_guild_local_id
            ON products(guild_id, local_id)
            WHERE guild_id IS NOT NULL AND local_id IS NOT NULL
            """
        )

        # Sequência independente por servidor. Isso evita que o ID local seja
        # reutilizado se o produto mais recente for apagado.
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS product_local_sequences(
                guild_id BIGINT PRIMARY KEY,
                last_id INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        con._conn.execute(
            """
            INSERT INTO product_local_sequences(guild_id, last_id)
            SELECT guild_id, COALESCE(MAX(local_id), 0)
            FROM products
            WHERE guild_id IS NOT NULL
            GROUP BY guild_id
            ON CONFLICT(guild_id) DO UPDATE SET
                last_id = GREATEST(
                    product_local_sequences.last_id,
                    excluded.last_id
                )
            """
        )

        # Trigger: qualquer módulo que criar um produto recebe automaticamente
        # o próximo ID LOCAL daquele servidor.
        con._conn.execute(
            """
            CREATE OR REPLACE FUNCTION assign_product_local_id()
            RETURNS TRIGGER AS $$
            DECLARE
                next_local INTEGER;
            BEGIN
                IF NEW.local_id IS NULL THEN
                    INSERT INTO product_local_sequences(guild_id, last_id)
                    VALUES (NEW.guild_id, 1)
                    ON CONFLICT(guild_id) DO UPDATE
                    SET last_id = product_local_sequences.last_id + 1
                    RETURNING last_id INTO next_local;

                    NEW.local_id := next_local;
                ELSE
                    INSERT INTO product_local_sequences(guild_id, last_id)
                    VALUES (NEW.guild_id, NEW.local_id)
                    ON CONFLICT(guild_id) DO UPDATE
                    SET last_id = GREATEST(
                        product_local_sequences.last_id,
                        NEW.local_id
                    );
                END IF;

                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
        con._conn.execute(
            "DROP TRIGGER IF EXISTS trg_assign_product_local_id ON products"
        )
        con._conn.execute(
            """
            CREATE TRIGGER trg_assign_product_local_id
            BEFORE INSERT ON products
            FOR EACH ROW
            EXECUTE FUNCTION assign_product_local_id()
            """
        )

        # Snapshot no pedido para auditoria/histórico.
        con._conn.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS split_user TEXT")
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS split_tax NUMERIC(5,2) DEFAULT 0"
        )
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS split_amount NUMERIC(12,2) DEFAULT 0"
        )
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS split_source TEXT"
        )
        con._conn.execute(
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS split_group TEXT"
        )
        con.commit()
    finally:
        con.close()


def ensure_affiliate_schema():
    """Afiliados, seleção por carrinho e terceiro repasse auditável."""
    con = db()
    try:
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS affiliates(
                id BIGSERIAL PRIMARY KEY,
                guild_id BIGINT NOT NULL,
                discord_user_id BIGINT NOT NULL,
                display_name TEXT NOT NULL,
                mistic_email TEXT NOT NULL,
                commission_percent NUMERIC(5,2) NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_by BIGINT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, discord_user_id)
            )
            """
        )
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cart_affiliates(
                channel_id BIGINT PRIMARY KEY,
                guild_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                affiliate_id BIGINT NOT NULL REFERENCES affiliates(id),
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        con._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS affiliate_subowners(
                guild_id BIGINT PRIMARY KEY,
                mistic_email TEXT NOT NULL,
                percent NUMERIC(5,2) NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        con._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_affiliates_guild_active
            ON affiliates(guild_id, active, display_name)
            """
        )
        con._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cart_affiliates_guild_user
            ON cart_affiliates(guild_id, user_id)
            """
        )

        # Snapshot completo no pedido: a venda continua auditável mesmo se a
        # configuração do streamer mudar no futuro.
        order_columns = (
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_id BIGINT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_user_id BIGINT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_name TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_email TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_percent NUMERIC(5,2) DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_amount NUMERIC(12,2) DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_email TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_percent NUMERIC(5,2) DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_amount NUMERIC(12,2) DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_payout_status TEXT DEFAULT 'not_required'",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_payout_id TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_payout_error TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_payout_attempts INTEGER DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS subowner_paid_at TIMESTAMP",
        )
        for statement in order_columns:
            con._conn.execute(statement)
        con.commit()
    finally:
        con.close()


def _validate_percent(value, label="Porcentagem"):
    percent = round(float(value or 0), 2)
    if percent <= 0 or percent >= 100:
        raise ValueError(f"{label} precisa ser maior que 0 e menor que 100.")
    return percent


def get_affiliates(guild_id, active_only=True):
    con = db()
    try:
        where = "AND active=1" if active_only else ""
        return con.execute(
            f"""
            SELECT * FROM affiliates
            WHERE guild_id=? {where}
            ORDER BY lower(display_name), id
            """,
            (int(guild_id),),
        ).fetchall()
    finally:
        con.close()


def get_affiliate(affiliate_id, guild_id=None):
    con = db()
    try:
        if guild_id is None:
            return con.execute(
                "SELECT * FROM affiliates WHERE id=?",
                (int(affiliate_id),),
            ).fetchone()
        return con.execute(
            "SELECT * FROM affiliates WHERE id=? AND guild_id=?",
            (int(affiliate_id), int(guild_id)),
        ).fetchone()
    finally:
        con.close()


def get_affiliate_by_member(guild_id, discord_user_id):
    con = db()
    try:
        return con.execute(
            "SELECT * FROM affiliates WHERE guild_id=? AND discord_user_id=?",
            (int(guild_id), int(discord_user_id)),
        ).fetchone()
    finally:
        con.close()


def get_cart_affiliate(channel_id, guild_id=None, user_id=None):
    con = db()
    try:
        row = con.execute(
            """
            SELECT a.*
            FROM cart_affiliates ca
            JOIN affiliates a ON a.id=ca.affiliate_id
            WHERE ca.channel_id=?
              AND a.active=1
            """,
            (int(channel_id),),
        ).fetchone()
    finally:
        con.close()
    if not row:
        return None
    if guild_id is not None and int(row["guild_id"]) != int(guild_id):
        return None
    # O user_id pertence ao registro do carrinho, não ao afiliado. A validação
    # de dono é feita antes de chamar esta função nas Views.
    return row


def set_cart_affiliate(channel_id, guild_id, user_id, affiliate_id):
    affiliate = get_affiliate(affiliate_id, guild_id)
    if not affiliate or int(affiliate["active"] or 0) != 1:
        raise ValueError("Afiliado indisponível.")
    con = db()
    try:
        con.execute(
            """
            INSERT INTO cart_affiliates(channel_id,guild_id,user_id,affiliate_id,updated_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(channel_id) DO UPDATE SET
                guild_id=excluded.guild_id,
                user_id=excluded.user_id,
                affiliate_id=excluded.affiliate_id,
                updated_at=excluded.updated_at
            """,
            (int(channel_id), int(guild_id), int(user_id), int(affiliate_id), now_iso()),
        )
        con.commit()
    finally:
        con.close()
    return affiliate


def clear_cart_affiliate(channel_id):
    con = db()
    try:
        con.execute("DELETE FROM cart_affiliates WHERE channel_id=?", (int(channel_id),))
        con.commit()
    finally:
        con.close()


def get_subowner(guild_id):
    con = db()
    try:
        return con.execute(
            "SELECT * FROM affiliate_subowners WHERE guild_id=? AND active=1",
            (int(guild_id),),
        ).fetchone()
    finally:
        con.close()


def affiliate_split_snapshot(channel_id, guild_id, final_amount):
    affiliate = get_cart_affiliate(channel_id, guild_id)
    if not affiliate:
        return None
    affiliate_percent = _validate_percent(
        affiliate["commission_percent"], "Comissão do afiliado"
    )
    subowner = get_subowner(guild_id)
    subowner_percent = (
        _validate_percent(subowner["percent"], "Porcentagem do subdono")
        if subowner
        else 0.0
    )
    if subowner and str(subowner["mistic_email"]).strip().lower() == str(
        affiliate["mistic_email"]
    ).strip().lower():
        raise ValueError("Afiliado e subdono não podem usar a mesma conta MisticPay.")
    if affiliate_percent + subowner_percent >= 100:
        raise ValueError(
            "A soma do afiliado e do subdono precisa deixar ao menos 1% para a conta principal."
        )
    amount = round(float(final_amount), 2)
    return {
        "affiliate": affiliate,
        "affiliate_percent": affiliate_percent,
        "affiliate_amount": round(amount * affiliate_percent / 100.0, 2),
        "subowner": subowner,
        "subowner_percent": subowner_percent,
        "subowner_amount": round(amount * subowner_percent / 100.0, 2),
        "principal_percent": round(100.0 - affiliate_percent - subowner_percent, 2),
    }


def validate_split_email(value):
    value = str(value or "").strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        raise ValueError("E-mail MisticPay inválido.")
    return value


def normalize_split_group(value):
    value = re.sub(r"\s+", " ", str(value or "")).strip().lower()
    if len(value) < 3:
        raise ValueError("Use pelo menos 3 caracteres.")
    if len(value) > 100:
        raise ValueError("O nome é muito grande.")
    return value


def normalize_panel_label(value):
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def panel_display_name(row):
    title = str(_row_value(row, "title", "") or "").strip()
    name = str(_row_value(row, "name", "") or "").strip()
    return title or name or f"Painel #{_row_value(row, 'id', '?')}"


def get_split_panels(guild_id, search=None, limit=100):
    """
    Lista painéis reais criados no bot.
    O nome exibido é o mesmo usado no embed: title, com fallback para name.
    """
    con = db()
    try:
        rows = con.execute(
            """
            SELECT id,guild_id,name,title
            FROM panels
            WHERE guild_id=?
            ORDER BY COALESCE(NULLIF(title,''),name) ASC,id ASC
            """,
            (int(guild_id),),
        ).fetchall()
    finally:
        con.close()

    current = normalize_panel_label(search)
    if current:
        rows = [
            row for row in rows
            if current in normalize_panel_label(panel_display_name(row))
            or current in normalize_panel_label(_row_value(row, "name", ""))
        ]
    return rows[: max(1, int(limit or 100))]


def resolve_split_panel(guild_id, value):
    """
    Resolve pelo NOME QUE APARECE NO PAINEL.
    Ex.: "Estabilizador Emulador".
    """
    wanted = normalize_panel_label(value)
    if not wanted:
        return None

    rows = get_split_panels(guild_id, limit=500)

    # Primeiro: correspondência exata com título visível ou nome interno.
    exact = [
        row for row in rows
        if normalize_panel_label(panel_display_name(row)) == wanted
        or normalize_panel_label(_row_value(row, "name", "")) == wanted
    ]
    if exact:
        # Se houver duplicado antigo, o mais recente vence.
        return sorted(exact, key=lambda r: int(_row_value(r, "id", 0) or 0), reverse=True)[0]

    # Depois: aceita um único resultado parcial para facilitar digitação.
    partial = [
        row for row in rows
        if wanted in normalize_panel_label(panel_display_name(row))
        or wanted in normalize_panel_label(_row_value(row, "name", ""))
    ]
    if len(partial) == 1:
        return partial[0]

    return None


def get_panel_products(guild_id, panel_id, active_only=False):
    con = db()
    try:
        query = """
            SELECT p.*
            FROM products p
            JOIN panel_products pp ON pp.product_id=p.id
            JOIN panels pn ON pn.id=pp.panel_id
            WHERE pp.panel_id=? AND pn.guild_id=? AND p.guild_id=?
        """
        args = [int(panel_id), int(guild_id), int(guild_id)]
        if active_only:
            query += " AND p.active=1"
        query += " ORDER BY p.local_id ASC,p.id ASC"
        return con.execute(query, tuple(args)).fetchall()
    finally:
        con.close()


async def split_panel_autocomplete(
    interaction: discord.Interaction,
    current: str,
):
    """Autocomplete mostra PAINÉIS, não a lista global de produtos."""
    if not interaction.guild_id:
        return []
    try:
        rows = get_split_panels(interaction.guild_id, current, limit=25)
    except Exception:
        return []

    choices = []
    seen = set()
    for row in rows:
        label = panel_display_name(row)
        key = normalize_panel_label(label)
        if not label or key in seen:
            continue
        seen.add(key)
        choices.append(
            app_commands.Choice(
                name=label[:100],
                value=label[:100],
            )
        )
        if len(choices) >= 25:
            break
    return choices


def mask_split_email(value):
    value = str(value or "")
    if "@" not in value:
        return "***"
    left, right = value.split("@", 1)
    return (left[:2] + "***@" + right) if left else ("***@" + right)


def get_split_group_rules(guild_id):
    con = db()
    try:
        return con.execute(
            """
            SELECT id,guild_id,match_text,split_user,split_tax,active,
                   panel_id,panel_name
            FROM split_group_rules
            WHERE guild_id=? AND active=1
            ORDER BY
                CASE WHEN panel_id IS NOT NULL THEN 0 ELSE 1 END,
                id DESC
            """,
            (int(guild_id),),
        ).fetchall()
    finally:
        con.close()


def find_panel_split_group(product):
    """
    Regra nova V4:
    produto herda o split do PAINEL ao qual ele foi ligado em panel_products.
    Assim Mensal / 90 Dias / Permanente recebem a mesma divisão mesmo tendo
    nomes de produto totalmente diferentes.
    """
    if not product:
        return None

    guild_id = int(_row_value(product, "guild_id", 0) or 0)
    product_id = int(_row_value(product, "id", 0) or 0)
    if not guild_id or not product_id:
        return None

    con = db()
    try:
        row = con.execute(
            """
            SELECT sgr.id,sgr.split_user,sgr.split_tax,
                   sgr.panel_id,sgr.panel_name,
                   pn.name AS real_panel_name,
                   pn.title AS real_panel_title
            FROM split_group_rules sgr
            JOIN panel_products pp ON pp.panel_id=sgr.panel_id
            LEFT JOIN panels pn ON pn.id=sgr.panel_id
            WHERE sgr.guild_id=?
              AND sgr.active=1
              AND sgr.panel_id IS NOT NULL
              AND pp.product_id=?
            ORDER BY sgr.id DESC
            LIMIT 1
            """,
            (guild_id, product_id),
        ).fetchone()
    finally:
        con.close()

    if not row:
        return None

    split_user = validate_split_email(_row_value(row, "split_user", ""))
    split_tax = round(float(_row_value(row, "split_tax", 0) or 0), 2)
    if split_tax <= 0 or split_tax >= 100:
        return None

    display = (
        str(_row_value(row, "panel_name", "") or "").strip()
        or str(_row_value(row, "real_panel_title", "") or "").strip()
        or str(_row_value(row, "real_panel_name", "") or "").strip()
        or f"Painel #{_row_value(row, 'panel_id', '?')}"
    )

    return {
        "user": split_user,
        "tax": split_tax,
        "source": "painel",
        "group": display,
        "panel_id": int(_row_value(row, "panel_id", 0) or 0),
    }


def find_matching_split_group(product):
    if not product:
        return None

    # V4: painel real tem prioridade sobre as regras antigas por texto.
    panel_rule = find_panel_split_group(product)
    if panel_rule:
        return panel_rule

    # Compatibilidade: regras antigas por nome-base continuam funcionando.
    guild_id = int(_row_value(product, "guild_id", 0) or 0)
    product_name = str(_row_value(product, "name", "") or "").strip().lower()
    if not guild_id or not product_name:
        return None

    for row in get_split_group_rules(guild_id):
        if _row_value(row, "panel_id", None) is not None:
            continue
        match_raw = str(_row_value(row, "match_text", "") or "")
        if not match_raw:
            continue
        match_text = normalize_split_group(match_raw)
        if match_text in product_name:
            split_user = validate_split_email(_row_value(row, "split_user", ""))
            split_tax = round(float(_row_value(row, "split_tax", 0) or 0), 2)
            if split_tax <= 0 or split_tax >= 100:
                continue
            return {
                "user": split_user,
                "tax": split_tax,
                "source": "grupo",
                "group": match_text,
            }
    return None


def get_product_split(product):
    """Prioridade: split individual > painel real > grupo legado por nome > sem split."""
    if not product:
        return None

    enabled = int(_row_value(product, "split_enabled", 0) or 0) == 1
    override = int(_row_value(product, "split_override", 0) or 0) == 1

    # Sistema antigo por ID continua funcionando e tem prioridade.
    if enabled:
        split_user = validate_split_email(_row_value(product, "split_user", ""))
        split_tax = round(float(_row_value(product, "split_tax", 0) or 0), 2)
        if split_tax <= 0 or split_tax >= 100:
            raise ValueError(
                "Split individual deste produto está inválido. Configure uma porcentagem entre 0 e 100."
            )
        return {
            "user": split_user,
            "tax": split_tax,
            "source": "produto",
            "group": None,
        }

    # Bloqueio individual explícito impede herança de painel/grupo.
    if override:
        return None

    return find_matching_split_group(product)

def get_product(pid):
    con = db()
    r = con.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    con.close()
    return r


def resolve_product_for_guild(product_id, guild_id, repair=True):
    """
    Resolve produto pelo ID LOCAL do servidor.

    Exemplo:
    - servidor A pode ter produto #1, #2, #3...
    - servidor B também pode ter produto #1, #2, #3...
    O products.id global continua interno e não é mostrado ao usuário.
    """
    con = db()
    try:
        product = con.execute(
            "SELECT * FROM products WHERE guild_id=? AND local_id=?",
            (guild_id, product_id),
        ).fetchone()
        if product:
            return product, "ok"

        return None, "missing"
    finally:
        con.close()


def get_order(oid):
    con = db()
    r = con.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    con.close()
    return r


def get_cfg(gid):
    con = db()
    r = con.execute("SELECT * FROM guild_config WHERE guild_id=?", (gid,)).fetchone()
    con.close()
    return r


def normalize_coupon_code(value):
    value = str(value or "").strip().upper()
    return re.sub(r"[^A-Z0-9_-]+", "", value)[:32]


def coupon_expiration(row):
    """Retorna o vencimento em UTC, aceitando datetime ou texto do banco."""
    value = row["expires_at"] if row and "expires_at" in row.keys() else None
    if not value:
        return None
    if isinstance(value, datetime):
        expires = value
    else:
        try:
            expires = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires.astimezone(timezone.utc)


def coupon_is_expired(row):
    expires = coupon_expiration(row)
    return bool(expires and expires <= datetime.now(timezone.utc))


def get_coupon(guild_id, coupon_code, product_id=None, include_inactive=False):
    """
    Busca cupom pelo código.
    Quando product_id é informado, valida que o cupom pertence àquele produto.
    """
    coupon_code = normalize_coupon_code(coupon_code)
    if not coupon_code:
        return None

    con = db()
    row = con.execute(
        "SELECT * FROM coupons WHERE guild_id=? AND code=?",
        (guild_id, coupon_code),
    ).fetchone()
    con.close()

    if not row:
        return None

    if not include_inactive and int(row["active"] or 0) != 1:
        return None

    if not include_inactive and coupon_is_expired(row):
        return None

    # Cupom antigo com product_id NULL continua compatível como cupom geral.
    coupon_product_id = row["product_id"]
    if product_id is not None and coupon_product_id is not None:
        if int(coupon_product_id) != int(product_id):
            return None

    max_uses = row["max_uses"]
    used_count = int(row["used_count"] or 0)
    if not include_inactive and max_uses is not None:
        if used_count >= int(max_uses):
            return None

    return row


def get_coupon_any_state(guild_id, coupon_code):
    coupon_code = normalize_coupon_code(coupon_code)
    if not coupon_code:
        return None
    con = db()
    row = con.execute(
        "SELECT * FROM coupons WHERE guild_id=? AND code=?",
        (guild_id, coupon_code),
    ).fetchone()
    con.close()
    return row


def get_saved_cart_coupon(channel_id):
    if not channel_id:
        return None
    con = db()
    row = con.execute(
        "SELECT * FROM cart_coupons WHERE channel_id=?",
        (channel_id,),
    ).fetchone()
    con.close()
    return row


def set_cart_coupon(
    channel_id,
    guild_id,
    user_id,
    product_id,
    coupon_code,
    discount_percent,
):
    con = db()
    con.execute(
        """
        INSERT INTO cart_coupons(
            channel_id,guild_id,user_id,product_id,
            coupon_code,discount_percent,updated_at
        ) VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(channel_id) DO UPDATE SET
            guild_id=excluded.guild_id,
            user_id=excluded.user_id,
            product_id=excluded.product_id,
            coupon_code=excluded.coupon_code,
            discount_percent=excluded.discount_percent,
            updated_at=excluded.updated_at
        """,
        (
            channel_id,
            guild_id,
            user_id,
            product_id,
            normalize_coupon_code(coupon_code),
            float(discount_percent),
            now_iso(),
        ),
    )
    con.commit()
    con.close()


def clear_cart_coupon(channel_id):
    if not channel_id:
        return
    con = db()
    con.execute("DELETE FROM cart_coupons WHERE channel_id=?", (channel_id,))
    con.commit()
    con.close()


def reserve_coupon_usage(guild_id, coupon_code, product_id):
    """
    Reserva UMA utilização do cupom de forma atômica antes de gerar o PIX.
    Evita que um cupom de 10 usos seja utilizado 11 vezes simultaneamente.
    """
    coupon_code = normalize_coupon_code(coupon_code)
    con = db()
    try:
        row = con.execute(
            """
            UPDATE coupons
            SET used_count=used_count+1,updated_at=?
            WHERE guild_id=?
              AND code=?
              AND active=1
              AND (expires_at IS NULL OR expires_at>CURRENT_TIMESTAMP)
              AND (product_id IS NULL OR product_id=?)
              AND (max_uses IS NULL OR used_count < max_uses)
            RETURNING id,code,used_count,max_uses
            """,
            (now_iso(), guild_id, coupon_code, product_id),
        ).fetchone()
        con.commit()
        return bool(row)
    finally:
        con.close()


def release_coupon_usage(guild_id, coupon_code):
    """Devolve a utilização se a geração do PIX falhar."""
    coupon_code = normalize_coupon_code(coupon_code)
    if not coupon_code:
        return
    con = db()
    try:
        con.execute(
            """
            UPDATE coupons
            SET used_count=CASE WHEN used_count>0 THEN used_count-1 ELSE 0 END,
                updated_at=?
            WHERE guild_id=? AND code=?
            """,
            (now_iso(), guild_id, coupon_code),
        )
        con.commit()
    finally:
        con.close()


def get_cart_pricing(channel_id, guild_id, base_price):
    base = round(float(base_price), 2)
    result = {
        "original": base,
        "coupon_code": None,
        "percent": 0.0,
        "discount": 0.0,
        "final": base,
    }

    saved = get_saved_cart_coupon(channel_id)
    if not saved or int(saved["guild_id"]) != int(guild_id):
        return result

    coupon = get_coupon(
        guild_id,
        saved["coupon_code"],
        product_id=saved["product_id"],
    )
    if not coupon:
        clear_cart_coupon(channel_id)
        return result

    percent = max(
        0.0,
        min(99.99, float(coupon["discount_percent"] or 0)),
    )
    discount = round(base * percent / 100.0, 2)
    final = round(max(0.01, base - discount), 2)

    result.update(
        {
            "coupon_code": coupon["code"],
            "percent": percent,
            "discount": discount,
            "final": final,
        }
    )
    return result


def build_cart_item_embed(product, pricing):
    item = discord.Embed(title="📦 Item do carrinho", color=0x17191D)
    item.add_field(name="Produto", value=f"`{product['name']}`", inline=False)
    item.add_field(name="Quantidade", value="`1`")
    item.add_field(name="Preço", value=f"`{money(pricing['original'])}`")
    item.add_field(
        name="Disponível",
        value="`∞`" if product["stock"] < 0 else f"`{product['stock']}`",
    )

    if pricing["coupon_code"]:
        item.add_field(
            name="🎟️ Cupom",
            value=(f"`{pricing['coupon_code']}` • **{pricing['percent']:g}% OFF**"),
            inline=False,
        )
        item.add_field(
            name="💸 Desconto",
            value=f"-{money(pricing['discount'])}",
            inline=True,
        )
        item.add_field(
            name="✅ Total com desconto",
            value=f"**{money(pricing['final'])}**",
            inline=True,
        )

    return item


def build_summary_embed(product, pricing):
    e = discord.Embed(
        title="ENTREGAS AUTOMÁTICAS | Resumo da Compra",
        color=0x8B2CF5,
    )
    e.add_field(name="📦 Produto", value=product["name"], inline=False)
    e.add_field(name="💵 Valor unitário", value=money(pricing["original"]))
    e.add_field(name="🔢 Quantidade", value="1")

    if pricing["coupon_code"]:
        e.add_field(
            name="🎟️ Cupom aplicado",
            value=(f"`{pricing['coupon_code']}` • **{pricing['percent']:g}% OFF**"),
            inline=False,
        )
        e.add_field(
            name="💸 Desconto",
            value=f"-{money(pricing['discount'])}",
            inline=True,
        )

    e.add_field(
        name="🛒 Total",
        value=f"**{money(pricing['final'])}**",
        inline=False,
    )
    return e


def _fernet():
    if not FERNET_KEY:
        raise RuntimeError(
            "MISTICPAY_FERNET_KEY não configurada nos Secrets do Replit. "
            "Gere uma única chave e mantenha-a fixa para proteger as credenciais dos clientes."
        )
    try:
        return Fernet(FERNET_KEY.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("MISTICPAY_FERNET_KEY inválida.") from exc


def encrypt_secret(value):
    return _fernet().encrypt(str(value).encode("utf-8")).decode("utf-8")


def decrypt_secret(value):
    try:
        return _fernet().decrypt(str(value).encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Não foi possível descriptografar a MisticPay deste servidor. "
            "A chave MISTICPAY_FERNET_KEY pode ter sido alterada."
        ) from exc


def mask_value(value, visible=4):
    value = str(value or "")
    if not value:
        return "não informado"
    if len(value) <= visible:
        return "•" * len(value)
    return value[:visible] + "•" * min(12, len(value) - visible)


def get_mistic_row(guild_id):
    con = db()
    row = con.execute(
        "SELECT * FROM guild_misticpay_credentials WHERE guild_id=?",
        (guild_id,),
    ).fetchone()
    con.close()
    return row


def get_mistic_credentials(guild_id, allow_global=True):
    row = get_mistic_row(guild_id)
    if row and int(row["active"] or 0) == 1:
        return (
            decrypt_secret(row["client_id_enc"]),
            decrypt_secret(row["client_secret_enc"]),
            "guild",
        )
    if allow_global and CI and CS:
        return CI, CS, "global"
    raise RuntimeError(
        "MisticPay não conectada neste servidor. Use /misticpay configurar."
    )


def save_mistic_credentials(guild_id, client_id, client_secret, account_data):
    account_data = account_data or {}
    con = db()
    con.execute(
        """
        INSERT INTO guild_misticpay_credentials(
            guild_id, client_id_enc, client_secret_enc,
            account_name, account_email, active, connected_at, updated_at
        ) VALUES(?,?,?,?,?,1,?,?)
        ON CONFLICT(guild_id) DO UPDATE SET
            client_id_enc=excluded.client_id_enc,
            client_secret_enc=excluded.client_secret_enc,
            account_name=excluded.account_name,
            account_email=excluded.account_email,
            active=1,
            connected_at=excluded.connected_at,
            updated_at=excluded.updated_at
        """,
        (
            guild_id,
            encrypt_secret(client_id),
            encrypt_secret(client_secret),
            str(account_data.get("name") or ""),
            str(account_data.get("email") or ""),
            now_iso(),
            now_iso(),
        ),
    )
    con.commit()
    con.close()


async def api(method, endpoint, payload=None, guild_id=None, credentials=None):
    if credentials is not None:
        client_id, client_secret = credentials
    elif guild_id is not None:
        client_id, client_secret, _source = get_mistic_credentials(guild_id)
    else:
        client_id, client_secret = CI, CS

    if not client_id or not client_secret:
        raise RuntimeError("Credenciais MisticPay não configuradas para este servidor.")

    headers = {"Content-Type": "application/json"}
    # As chaves novas pk_/sk_ usam HTTP Basic e são necessárias para repasse
    # interno. As credenciais legadas ci_/cs_ continuam nos dois endpoints
    # antigos de criar/consultar PIX.
    if str(client_id).startswith("pk_") and str(client_secret).startswith("sk_"):
        basic = base64.b64encode(
            f"{client_id}:{client_secret}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {basic}"
    else:
        headers["ci"] = client_id
        headers["cs"] = client_secret

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25)) as sess:
        async with sess.request(
            method,
            MISTIC_BASE + endpoint,
            headers=headers,
            json=payload,
        ) as resp:
            txt = await resp.text()
            try:
                data = json.loads(txt)
            except Exception:
                data = {"raw": txt}
            if resp.status >= 400:
                raise RuntimeError(
                    data.get("message") or data.get("error") or f"HTTP {resp.status}"
                )
            return data


async def test_mistic_credentials(client_id, client_secret):
    result = await api(
        "GET",
        "/users/info",
        credentials=(client_id, client_secret),
    )
    return result.get("data") or result.get("user") or result or {}


async def create_pix(
    guild_id,
    amount,
    name,
    document,
    local_id,
    description,
    split_user=None,
    split_tax=None,
):
    payload = {
        "amount": round(float(amount), 2),
        "payerName": name[:120],
        "payerDocument": clean_doc(document),
        "transactionId": local_id[:100],
        "description": description[:250],
    }

    # Split nativo da MisticPay. A conta autenticada continua sendo a
    # recebedora principal; splitUser recebe splitTax% da transação.
    if split_user is not None or split_tax is not None:
        split_user = validate_split_email(split_user)
        split_tax = round(float(split_tax or 0), 2)
        if split_tax <= 0 or split_tax >= 100:
            raise ValueError("Porcentagem de split inválida.")
        payload["splitUser"] = split_user
        payload["splitTax"] = split_tax

    if PUBLIC_BASE_URL and WEBHOOK_TOKEN:
        payload["projectWebhook"] = (
            f"{PUBLIC_BASE_URL}/webhooks/misticpay/{WEBHOOK_TOKEN}"
        )

    return await api(
        "POST",
        "/transactions/create",
        payload,
        guild_id=guild_id,
    )


def mistic_supports_internal_payout(guild_id):
    client_id, client_secret, _source = get_mistic_credentials(guild_id)
    return str(client_id).startswith("pk_") and str(client_secret).startswith("sk_")


async def create_internal_payout(guild_id, email, amount, description):
    if not mistic_supports_internal_payout(guild_id):
        raise RuntimeError(
            "O split de 3 pessoas exige uma Chave de Acesso MisticPay pk_/sk_ "
            "com permissão cashout. Credenciais ci_/cs_ só suportam o split nativo de 2 contas."
        )
    return await api(
        "POST",
        "/transactions/withdraw/internal",
        {
            "email": validate_split_email(email),
            "amount": round(float(amount), 2),
            "description": str(description)[:250],
        },
        guild_id=guild_id,
    )


async def check_pix(guild_id, tid):
    return await api(
        "POST",
        "/transactions/check",
        {"transactionId": str(tid)},
        guild_id=guild_id,
    )


class LinkView(discord.ui.View):
    def __init__(self, url):
        super().__init__(timeout=300)
        self.add_item(discord.ui.Button(label="🛒 Ir para o Carrinho", url=url))


async def open_cart(interaction, product_id):
    p = get_product(product_id)
    if not p or not p["active"] or p["stock"] == 0:
        await interaction.followup.send("❌ Produto indisponível.", ephemeral=True)
        return
    guild = interaction.guild
    cfg = get_cfg(guild.id)
    cat = (
        guild.get_channel(cfg["cart_category_id"])
        if cfg and cfg["cart_category_id"]
        else None
    )
    if not isinstance(cat, discord.CategoryChannel):
        cat = discord.utils.get(
            guild.categories, name="🛒 Carrinhos"
        ) or await guild.create_category("🛒 Carrinhos")
        con = db()
        con.execute(
            "UPDATE guild_config SET cart_category_id=? WHERE guild_id=?",
            (cat.id, guild.id),
        )
        con.commit()
        con.close()
    existing = next(
        (
            c
            for c in cat.text_channels
            if c.name.startswith(f"carrinho-{interaction.user.id}")
        ),
        None,
    )
    if existing:
        await interaction.followup.send(
            f"Você já tem um carrinho: {existing.mention}", ephemeral=True
        )
        return
    ow = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        interaction.user: discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True
        ),
        guild.me: discord.PermissionOverwrite(
            view_channel=True, send_messages=True, manage_channels=True
        ),
    }
    ch = await guild.create_text_channel(
        f"carrinho-{interaction.user.id}",
        category=cat,
        overwrites=ow,
        topic=f"user={interaction.user.id};product={product_id}",
    )
    e = discord.Embed(
        title="ENTREGAS AUTOMÁTICAS | Carrinho aberto",
        description=f"✅ {interaction.user.mention}, seu carrinho foi aberto com sucesso.",
        color=0x8B2CF5,
    )
    channel_url = f"https://discord.com/channels/{guild.id}/{ch.id}"
    await interaction.followup.send(embed=e, view=LinkView(channel_url), ephemeral=True)
    intro = discord.Embed(
        title="ENTREGAS AUTOMÁTICAS | Sistema de compra",
        description=f"📣 Olá {interaction.user.mention}, confira seu produto abaixo.\n\n📕 Leia os termos antes de continuar.\n\n🔐 **Por exigência da instituição financeira, precisamos do CPF apenas para emissão do PIX. O dado não será publicado no servidor.**",
        color=0x8B2CF5,
    )
    if valid_url(p["banner_url"]):
        intro.set_image(url=p["banner_url"])
    await ch.send(
        interaction.user.mention,
        embed=intro,
        view=StartView(product_id, interaction.user.id),
    )
    pricing = get_cart_pricing(ch.id, guild.id, p["price"])
    item = build_cart_item_embed(p, pricing)
    await ch.send(
        embed=item,
        view=CartItemView(product_id, interaction.user.id),
    )


class CouponModal(discord.ui.Modal, title="Inserir cupom"):
    def __init__(self, pid, uid, source_message=None, source_mode="cart"):
        super().__init__(timeout=600)
        self.pid = pid
        self.uid = uid
        self.source_message = source_message
        self.source_mode = source_mode
        self.coupon = discord.ui.TextInput(
            label="Insira o cupom abaixo:",
            placeholder="Ex: LINK",
            min_length=1,
            max_length=32,
        )
        self.add_item(self.coupon)

    async def on_submit(self, i):
        if i.user.id != self.uid:
            await i.response.send_message(
                "❌ Este carrinho pertence a outra pessoa.",
                ephemeral=True,
            )
            return

        coupon_code = normalize_coupon_code(str(self.coupon))
        product = get_product(self.pid)
        if not product or int(product["guild_id"]) != i.guild.id:
            await i.response.send_message("❌ Produto não encontrado.", ephemeral=True)
            return

        coupon_any = get_coupon_any_state(i.guild.id, coupon_code)
        if not coupon_any:
            await i.response.send_message(
                "❌ Cupom não encontrado.",
                ephemeral=True,
            )
            return

        if int(coupon_any["active"] or 0) != 1:
            await i.response.send_message(
                "❌ Este cupom está desativado.",
                ephemeral=True,
            )
            return

        if coupon_is_expired(coupon_any):
            await i.response.send_message(
                "❌ Este cupom expirou.",
                ephemeral=True,
            )
            return

        if coupon_any["product_id"] is not None and int(
            coupon_any["product_id"]
        ) != int(self.pid):
            await i.response.send_message(
                "❌ Este cupom não é válido para este produto.",
                ephemeral=True,
            )
            return

        max_uses = coupon_any["max_uses"]
        used_count = int(coupon_any["used_count"] or 0)
        if max_uses is not None and used_count >= int(max_uses):
            await i.response.send_message(
                "❌ Este cupom esgotou todas as utilizações.",
                ephemeral=True,
            )
            return

        coupon = coupon_any

        set_cart_coupon(
            i.channel.id,
            i.guild.id,
            i.user.id,
            self.pid,
            coupon["code"],
            coupon["discount_percent"],
        )
        pricing = get_cart_pricing(i.channel.id, i.guild.id, product["price"])

        await i.response.defer(ephemeral=True)

        if self.source_message:
            try:
                if self.source_mode == "summary":
                    await self.source_message.edit(
                        embed=build_summary_embed(product, pricing),
                        view=SummaryView(self.pid, self.uid),
                    )
                else:
                    await self.source_message.edit(
                        embed=build_cart_item_embed(product, pricing),
                        view=CartItemView(self.pid, self.uid),
                    )
            except Exception as exc:
                print(f"Não consegui atualizar visualmente o carrinho: {exc}")

        await i.followup.send(
            f"✅ Cupom **{coupon['code']}** aplicado!\n"
            f"🎟️ Desconto: **{pricing['percent']:g}%**\n"
            f"💸 Você economizou **{money(pricing['discount'])}**\n"
            f"💰 Novo total: **{money(pricing['final'])}**",
            ephemeral=True,
        )


def build_affiliates_embed(guild_id, selected_id=None, page=0, page_size=20):
    rows = get_affiliates(guild_id)
    pages = max(1, math.ceil(len(rows) / page_size))
    page = max(0, min(int(page), pages - 1))
    start = page * page_size
    visible = rows[start : start + page_size]
    lines = []
    for row in visible:
        mark = "✅" if selected_id and int(row["id"]) == int(selected_id) else "▫️"
        lines.append(
            f"{mark} <@{row['discord_user_id']}> • "
            f"**{float(row['commission_percent']):g}%**"
        )
    description = (
        "Selecione quem indicou esta compra. A escolha ficará registrada no pedido.\n\n"
        + ("\n".join(lines) if lines else "Nenhum afiliado cadastrado neste servidor.")
    )
    embed = discord.Embed(
        title="🤝 Afiliados • Lock Sensi",
        description=description[:4000],
        color=0xE31B2B,
    )
    embed.set_footer(text=f"Página {page + 1}/{pages} • {len(rows)} afiliado(s)")
    return embed, rows, page, pages


class AffiliateSelect(discord.ui.Select):
    def __init__(self, owner_view, visible_rows, selected_id=None):
        self.owner_view = owner_view
        options = []
        for row in visible_rows[:25]:
            options.append(
                discord.SelectOption(
                    label=str(row["display_name"])[:100],
                    description=f"Comissão: {float(row['commission_percent']):g}%",
                    value=str(row["id"]),
                    emoji="📣",
                    default=bool(selected_id and int(row["id"]) == int(selected_id)),
                )
            )
        if not options:
            options.append(
                discord.SelectOption(
                    label="Nenhum afiliado disponível",
                    value="none",
                    emoji="⚠️",
                )
            )
        super().__init__(
            placeholder="Selecione quem indicou você...",
            min_values=1,
            max_values=1,
            options=options,
        )

    async def callback(self, i: discord.Interaction):
        if i.user.id != self.owner_view.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        if self.values[0] == "none":
            await i.response.send_message("❌ Nenhum afiliado cadastrado.", ephemeral=True)
            return
        try:
            candidate = get_affiliate(int(self.values[0]), i.guild.id)
            if candidate and int(candidate["discord_user_id"]) == int(i.user.id):
                await i.response.send_message(
                    "❌ Você não pode atribuir sua própria compra a você mesmo.",
                    ephemeral=True,
                )
                return
            affiliate = set_cart_affiliate(
                self.owner_view.channel_id,
                i.guild.id,
                i.user.id,
                int(self.values[0]),
            )
        except Exception as exc:
            await i.response.send_message(f"❌ {str(exc)[:300]}", ephemeral=True)
            return
        embed, _rows, page, _pages = build_affiliates_embed(
            i.guild.id,
            selected_id=affiliate["id"],
            page=self.owner_view.page,
        )
        await i.response.edit_message(
            embed=embed,
            view=AffiliatePickerView(
                i.guild.id,
                self.owner_view.channel_id,
                self.owner_view.uid,
                page=page,
            ),
        )


class AffiliatePickerView(discord.ui.View):
    def __init__(self, guild_id, channel_id, uid, page=0):
        super().__init__(timeout=600)
        self.guild_id = int(guild_id)
        self.channel_id = int(channel_id)
        self.uid = int(uid)
        current = get_cart_affiliate(channel_id, guild_id)
        self.selected_id = int(current["id"]) if current else None
        _embed, rows, self.page, self.pages = build_affiliates_embed(
            guild_id, self.selected_id, page
        )
        start = self.page * 20
        self.add_item(AffiliateSelect(self, rows[start : start + 20], self.selected_id))
        self.previous.disabled = self.page <= 0
        self.next.disabled = self.page >= self.pages - 1

    async def _turn_page(self, i, page):
        embed, _rows, page, _pages = build_affiliates_embed(
            self.guild_id, self.selected_id, page
        )
        await i.response.edit_message(
            embed=embed,
            view=AffiliatePickerView(
                self.guild_id, self.channel_id, self.uid, page=page
            ),
        )

    @discord.ui.button(label="◀", style=discord.ButtonStyle.secondary, row=1)
    async def previous(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        await self._turn_page(i, self.page - 1)

    @discord.ui.button(label="▶", style=discord.ButtonStyle.secondary, row=1)
    async def next(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        await self._turn_page(i, self.page + 1)

    @discord.ui.button(
        label="Remover indicação", style=discord.ButtonStyle.danger, row=1
    )
    async def remove(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        clear_cart_affiliate(self.channel_id)
        embed, _rows, page, _pages = build_affiliates_embed(
            self.guild_id, None, self.page
        )
        await i.response.edit_message(
            embed=embed,
            view=AffiliatePickerView(
                self.guild_id, self.channel_id, self.uid, page=page
            ),
        )


async def open_affiliate_picker(i, pid, uid):
    if i.user.id != uid:
        await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
        return
    current = get_cart_affiliate(i.channel.id, i.guild.id)
    selected_id = int(current["id"]) if current else None
    embed, _rows, page, _pages = build_affiliates_embed(
        i.guild.id, selected_id, 0
    )
    await i.response.send_message(
        embed=embed,
        view=AffiliatePickerView(i.guild.id, i.channel.id, uid, page),
        ephemeral=True,
    )


class CartItemView(discord.ui.View):
    def __init__(self, pid, uid):
        super().__init__(timeout=1800)
        self.pid = pid
        self.uid = uid

    @discord.ui.button(label="🎟️ Cupom", style=discord.ButtonStyle.secondary)
    async def coupon(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message(
                "Carrinho de outra pessoa.",
                ephemeral=True,
            )
            return
        await i.response.send_modal(
            CouponModal(
                self.pid,
                self.uid,
                source_message=i.message,
                source_mode="cart",
            )
        )

    @discord.ui.button(label="🤝 Afiliados", style=discord.ButtonStyle.secondary)
    async def affiliate(self, i, b):
        await open_affiliate_picker(i, self.pid, self.uid)


class StartView(discord.ui.View):
    def __init__(self, pid, uid):
        super().__init__(timeout=1800)
        self.pid = pid
        self.uid = uid

    async def ok(self, i):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return False
        return True

    @discord.ui.button(
        label="✅ Aceitar e Continuar", style=discord.ButtonStyle.success
    )
    async def go(self, i, b):
        if not await self.ok(i):
            return
        p = get_product(self.pid)
        pricing = get_cart_pricing(i.channel.id, i.guild.id, p["price"])
        e = build_summary_embed(p, pricing)
        affiliate = get_cart_affiliate(i.channel.id, i.guild.id)
        if affiliate:
            e.add_field(
                name="🤝 Afiliado selecionado",
                value=(
                    f"<@{affiliate['discord_user_id']}> • "
                    f"{float(affiliate['commission_percent']):g}%"
                ),
                inline=False,
            )
        await i.response.send_message(
            embed=e,
            view=SummaryView(self.pid, self.uid),
        )

    @discord.ui.button(label="❌ Cancelar", style=discord.ButtonStyle.danger)
    async def cancel(self, i, b):
        if not await self.ok(i):
            return
        clear_cart_coupon(i.channel.id)
        clear_cart_affiliate(i.channel.id)
        await i.response.send_message("Compra cancelada. Canal será apagado.")
        await asyncio.sleep(4)
        try:
            await i.channel.delete()
        except discord.NotFound:
            pass
        except Exception as exc:
            print(f"Erro ao apagar carrinho cancelado: {exc}")

    @discord.ui.button(label="📋 Ler os Termos", style=discord.ButtonStyle.secondary)
    async def terms(self, i, b):
        if not await self.ok(i):
            return
        cfg = get_cfg(i.guild.id)
        await i.response.send_message(
            (cfg["terms_url"] if cfg and cfg["terms_url"] else "") or TERMS_URL,
            ephemeral=True,
        )


class SummaryView(discord.ui.View):
    def __init__(self, pid, uid):
        super().__init__(timeout=1800)
        self.pid = pid
        self.uid = uid

    @discord.ui.button(
        label="✅ Ir para o Pagamento", style=discord.ButtonStyle.success
    )
    async def pay(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        p = get_product(self.pid)
        pricing = get_cart_pricing(i.channel.id, i.guild.id, p["price"])
        e = discord.Embed(
            title="ENTREGAS AUTOMÁTICAS | Sistema de pagamento",
            description="Escolha a forma de pagamento.",
            color=0x8B2CF5,
        )
        e.add_field(name="Produto", value=f"{p['name']} x1", inline=False)
        if pricing["coupon_code"]:
            e.add_field(
                name="🎟️ Cupom",
                value=f"`{pricing['coupon_code']}` • {pricing['percent']:g}% OFF",
                inline=False,
            )
            e.add_field(
                name="Valor original",
                value=money(pricing["original"]),
                inline=True,
            )
            e.add_field(
                name="Desconto",
                value=f"-{money(pricing['discount'])}",
                inline=True,
            )
        e.add_field(
            name="💰 Valor a pagar",
            value=f"**{money(pricing['final'])}**",
            inline=False,
        )
        affiliate = get_cart_affiliate(i.channel.id, i.guild.id)
        if affiliate:
            e.add_field(
                name="🤝 Afiliado selecionado",
                value=f"<@{affiliate['discord_user_id']}> • indicação registrada",
                inline=False,
            )
        await i.response.send_message(
            embed=e,
            view=PaymentView(self.pid, self.uid),
        )

    @discord.ui.button(label="🎟️ Cupom", style=discord.ButtonStyle.secondary)
    async def coupon(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        await i.response.send_modal(
            CouponModal(
                self.pid,
                self.uid,
                source_message=i.message,
                source_mode="summary",
            )
        )

    @discord.ui.button(label="🤝 Afiliados", style=discord.ButtonStyle.secondary)
    async def affiliate(self, i, b):
        await open_affiliate_picker(i, self.pid, self.uid)

    @discord.ui.button(label="❌ Cancelar Compra", style=discord.ButtonStyle.danger)
    async def cancel(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        clear_cart_coupon(i.channel.id)
        clear_cart_affiliate(i.channel.id)
        await i.response.send_message("Compra cancelada.")
        await asyncio.sleep(3)
        try:
            await i.channel.delete()
        except discord.NotFound:
            pass
        except Exception as exc:
            print(f"Erro ao apagar carrinho cancelado: {exc}")


class PaymentView(discord.ui.View):
    def __init__(self, pid, uid):
        super().__init__(timeout=1800)
        self.pid = pid
        self.uid = uid

    @discord.ui.button(label="💠 PIX", style=discord.ButtonStyle.primary)
    async def pix(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        await i.response.send_modal(PayerModal(self.pid, self.uid))

    @discord.ui.button(label="❌ Cancelar", style=discord.ButtonStyle.danger)
    async def cancel(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        clear_cart_coupon(i.channel.id)
        clear_cart_affiliate(i.channel.id)
        await i.response.send_message("Cancelado.")
        await asyncio.sleep(3)
        try:
            await i.channel.delete()
        except discord.NotFound:
            pass
        except Exception as exc:
            print(f"Erro ao apagar carrinho cancelado: {exc}")


class PayerModal(discord.ui.Modal, title="Dados para gerar o PIX"):
    def __init__(self, pid, uid):
        super().__init__(timeout=600)
        self.pid = pid
        self.uid = uid
        self.name = discord.ui.TextInput(label="Nome completo", max_length=120)
        self.email = discord.ui.TextInput(
            label="E-mail", placeholder="seuemail@gmail.com", max_length=150
        )
        self.cpf = discord.ui.TextInput(
            label="CPF exigido pela instituição financeira",
            placeholder="11 números — não será publicado",
            min_length=11,
            max_length=14,
        )
        self.add_item(self.name)
        self.add_item(self.email)
        self.add_item(self.cpf)

    async def on_submit(self, i):
        if i.user.id != self.uid:
            await i.response.send_message("Carrinho de outra pessoa.", ephemeral=True)
            return
        doc = clean_doc(str(self.cpf))
        if len(doc) != 11 or len(set(doc)) < 2:
            await i.response.send_message("❌ CPF inválido.", ephemeral=True)
            return
        if "@" not in str(self.email):
            await i.response.send_message("❌ E-mail inválido.", ephemeral=True)
            return

        await i.response.defer(thinking=True)

        p = get_product(self.pid)
        pricing = get_cart_pricing(i.channel.id, i.guild.id, p["price"])
        final_amount = pricing["final"]

        # Sem afiliado, preserva exatamente o split antigo de duas contas.
        # Com afiliado, o split nativo envia a comissão ao streamer. Se houver
        # subdono, o segundo repasse acontece após a confirmação do pagamento.
        try:
            affiliate_split = affiliate_split_snapshot(
                i.channel.id, i.guild.id, final_amount
            )
            split = None if affiliate_split else get_product_split(p)
        except ValueError as exc:
            await i.followup.send(
                f"❌ O split deste produto está configurado incorretamente: `{exc}`\n"
                "Avise um administrador antes de tentar pagar.",
                ephemeral=True,
            )
            return

        if affiliate_split:
            affiliate = affiliate_split["affiliate"]
            subowner = affiliate_split["subowner"]
            split_user = str(affiliate["mistic_email"])
            split_tax = affiliate_split["affiliate_percent"]
            split_amount = affiliate_split["affiliate_amount"]
            split_source = "afiliado"
            split_group = str(affiliate["display_name"])
            subowner_email = str(subowner["mistic_email"]) if subowner else None
            subowner_percent = affiliate_split["subowner_percent"]
            subowner_amount = affiliate_split["subowner_amount"]
            if subowner and not mistic_supports_internal_payout(i.guild.id):
                await i.followup.send(
                    "❌ O modo de **3 participantes** está configurado, mas a conta "
                    "MisticPay usa credenciais antigas. Conecte uma Chave de Acesso "
                    "`pk_`/`sk_` com permissão **cashout**. Nenhum PIX foi criado.",
                    ephemeral=True,
                )
                return
        else:
            affiliate = None
            split_user = split["user"] if split else None
            split_tax = split["tax"] if split else 0.0
            split_amount = (
                round(final_amount * split_tax / 100.0, 2) if split else 0.0
            )
            split_source = split.get("source") if split else "nenhum"
            split_group = split.get("group") if split else None
            subowner_email = None
            subowner_percent = 0.0
            subowner_amount = 0.0

        # Se existe cupom, reserva 1 utilização antes de criar o PIX.
        coupon_reserved = False
        if pricing["coupon_code"]:
            coupon_reserved = reserve_coupon_usage(
                i.guild.id,
                pricing["coupon_code"],
                self.pid,
            )
            if not coupon_reserved:
                clear_cart_coupon(i.channel.id)
                await i.followup.send(
                    "❌ Este cupom acabou de esgotar ou foi desativado. "
                    "O PIX não foi gerado. Volte ao carrinho e tente novamente.",
                    ephemeral=True,
                )
                return

        con = db()
        cur = con.cursor()
        local = f"EA-{code(12)}"
        try:
            cur.execute(
                """
            INSERT INTO orders(
                guild_id,user_id,product_id,product_name,amount,
                original_amount,coupon_code,coupon_percent,discount_amount,
                split_user,split_tax,split_amount,split_source,split_group,
                affiliate_id,affiliate_user_id,affiliate_name,affiliate_email,
                affiliate_percent,affiliate_amount,
                subowner_email,subowner_percent,subowner_amount,
                subowner_payout_status,
                status,code,payer_name,payer_document,payer_email,
                cart_channel_id,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
                (
                    i.guild.id,
                    i.user.id,
                    self.pid,
                    p["name"],
                    final_amount,
                    pricing["original"],
                    pricing["coupon_code"],
                    pricing["percent"],
                    pricing["discount"],
                    split_user,
                    split_tax,
                    split_amount,
                    split_source,
                    split_group,
                    int(affiliate["id"]) if affiliate else None,
                    int(affiliate["discord_user_id"]) if affiliate else None,
                    str(affiliate["display_name"]) if affiliate else None,
                    str(affiliate["mistic_email"]) if affiliate else None,
                    split_tax if affiliate else 0.0,
                    split_amount if affiliate else 0.0,
                    subowner_email,
                    subowner_percent,
                    subowner_amount,
                    "pending" if subowner_amount > 0 else "not_required",
                    "pendente",
                    local,
                    str(self.name),
                    doc,
                    str(self.email),
                    i.channel.id,
                    now_iso(),
                ),
            )
            oid = cur.lastrowid
            con.commit()
        except Exception:
            con.rollback()
            if coupon_reserved:
                release_coupon_usage(i.guild.id, pricing["coupon_code"])
            raise
        finally:
            con.close()

        if split or affiliate_split:
            print(
                f"[SPLIT] pedido=#{oid} produto=#{_row_value(p, 'local_id', '?')} "
                f"fonte={split_source} grupo={split_group or '-'} tax={split_tax:g}% "
                f"destino={mask_split_email(split_user)} valor_split={money(split_amount)}",
                flush=True,
            )
        else:
            print(
                f"[SPLIT] pedido=#{oid} produto=#{_row_value(p, 'local_id', '?')} "
                "fonte=nenhum -> 100% conta principal",
                flush=True,
            )

        try:
            res = await create_pix(
                i.guild.id,
                final_amount,
                str(self.name),
                doc,
                f"EA-{oid}-{local}",
                f"{p['name']} - Discord {i.user.id}",
                split_user=split_user,
                split_tax=split_tax if (split or affiliate_split) else None,
            )
            data = res.get("data") or {}
            tid = str(data.get("transactionId") or "")
            cp = data.get("copyPaste") or ""
            qr = data.get("qrcodeUrl") or ""
            q64 = data.get("qrCodeBase64") or ""

            con = db()
            con.execute(
                "UPDATE orders SET transaction_id=?,pix_code=?,qr_url=?,updated_at=? WHERE id=?",
                (tid, cp, qr, now_iso(), oid),
            )
            con.commit()
            con.close()

            file = None
            if q64 and "," in q64:
                try:
                    file = discord.File(
                        io.BytesIO(base64.b64decode(q64.split(",", 1)[1])),
                        filename="pix.png",
                    )
                except Exception:
                    pass

            e = discord.Embed(
                title="💜 Pagamento PIX gerado",
                description=(
                    f"Pedido **#{oid}: {p['name']}**\n"
                    "A entrega será automática após a confirmação."
                ),
                color=0x8B2CF5,
            )
            if pricing["coupon_code"]:
                e.add_field(
                    name="🎟️ Cupom aplicado",
                    value=(
                        f"`{pricing['coupon_code']}` • **{pricing['percent']:g}% OFF**"
                    ),
                    inline=False,
                )
                e.add_field(
                    name="💵 Valor original",
                    value=money(pricing["original"]),
                    inline=True,
                )
                e.add_field(
                    name="💸 Desconto",
                    value=f"-{money(pricing['discount'])}",
                    inline=True,
                )
            e.add_field(
                name="💰 Valor do PIX",
                value=f"**{money(final_amount)}**",
                inline=False,
            )
            if affiliate_split:
                e.add_field(
                    name="🤝 Divisão por afiliado",
                    value=(
                        f"Conta principal: **{affiliate_split['principal_percent']:g}%**\n"
                        f"Afiliado <@{affiliate['discord_user_id']}>: **{split_tax:g}%**\n"
                        + (
                            f"Subdono: **{subowner_percent:g}%**\n"
                            "Repasse do subdono: **automático após confirmação**"
                            if subowner_amount > 0
                            else "Subdono: **não configurado**"
                        )
                    ),
                    inline=False,
                )
            elif split:
                e.add_field(
                    name="🤝 Divisão automática",
                    value=(
                        f"Conta principal: **{100 - split_tax:g}%**\n"
                        f"Parceiro: **{split_tax:g}%**\n"
                        f"Regra: **{'grupo ' + split_group if split_group else 'produto individual'}**"
                    ),
                    inline=False,
                )
            e.add_field(name="📡 Status", value="🟡 Aguardando pagamento")
            e.add_field(
                name="🧾 Identificador",
                value=f"`{tid or local}`",
                inline=False,
            )
            e.add_field(
                name="📋 PIX copia e cola",
                value=f"```{cp[:950]}```",
                inline=False,
            )
            if file:
                e.set_image(url="attachment://pix.png")
            elif valid_url(qr):
                e.set_image(url=qr)

            await i.followup.send(
                embed=e,
                file=file,
                view=VerifyView(oid, self.uid),
            )
        except Exception as ex:
            if coupon_reserved:
                release_coupon_usage(i.guild.id, pricing["coupon_code"])
            con = db()
            con.execute(
                "UPDATE orders SET status='falha',updated_at=? WHERE id=?",
                (now_iso(), oid),
            )
            con.commit()
            con.close()
            await i.followup.send(f"❌ Erro ao gerar PIX: `{str(ex)[:300]}`")


class VerifyView(discord.ui.View):
    def __init__(self, oid, uid):
        super().__init__(timeout=3600)
        self.oid = oid
        self.uid = uid

    @discord.ui.button(
        label="🔄 Verificar pagamento", style=discord.ButtonStyle.primary
    )
    async def check(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message("Pagamento de outra pessoa.", ephemeral=True)
            return
        await i.response.defer(ephemeral=True, thinking=True)
        ok, msg = await verify(self.oid)
        await i.followup.send(msg, ephemeral=True)

    @discord.ui.button(
        label="Copiar PIX",
        emoji="📋",
        style=discord.ButtonStyle.secondary,
    )
    async def copy_pix(self, i, b):
        if i.user.id != self.uid:
            await i.response.send_message(
                "Pagamento de outra pessoa.",
                ephemeral=True,
            )
            return

        order = get_order(self.oid)
        pix_code = str(order["pix_code"] or "").strip() if order else ""
        if not pix_code:
            await i.response.send_message(
                "❌ O código PIX deste pedido não está disponível.",
                ephemeral=True,
            )
            return

        # Envia somente o payload original. Alterar/remover caracteres pode
        # invalidar o PIX; o bloco do Discord oferece o ícone de copiar.
        await i.response.send_message(f"```{pix_code[:1900]}```", ephemeral=True)


async def process_subowner_payout(oid):
    """Faz o terceiro repasse uma única vez, com claim atômico no banco."""
    order = get_order(oid)
    if not order or str(order["status"]) != "aprovado":
        return False, "pedido ainda não aprovado"
    if int(_row_value(order, "is_test", 0) or 0) == 1:
        return False, "pedido de teste"
    amount = round(float(_row_value(order, "subowner_amount", 0) or 0), 2)
    email = str(_row_value(order, "subowner_email", "") or "").strip()
    status = str(
        _row_value(order, "subowner_payout_status", "not_required")
        or "not_required"
    )
    if not email or amount <= 0 or status == "not_required":
        return False, "sem terceiro repasse"
    if status == "paid":
        return True, "terceiro repasse já realizado"

    con = db()
    try:
        claimed = con.execute(
            """
            UPDATE orders
            SET subowner_payout_status='processing',
                subowner_payout_attempts=COALESCE(subowner_payout_attempts,0)+1,
                subowner_payout_error=NULL,
                updated_at=?
            WHERE id=?
              AND subowner_payout_status IN ('pending','failed')
              AND COALESCE(subowner_payout_attempts,0)<5
            RETURNING *
            """,
            (now_iso(), int(oid)),
        ).fetchone()
        con.commit()
    finally:
        con.close()
    if not claimed:
        return False, "repasse já está sendo processado ou excedeu as tentativas"

    try:
        result = await create_internal_payout(
            int(claimed["guild_id"]),
            email,
            amount,
            f"Subdono pedido #{oid} - {claimed['product_name']}",
        )
        data = result.get("data") or result
        payout_id = str(
            data.get("transactionId") or data.get("jobId") or data.get("id") or ""
        )
        con = db()
        try:
            con.execute(
                """
                UPDATE orders
                SET subowner_payout_status='paid',subowner_payout_id=?,
                    subowner_payout_error=NULL,subowner_paid_at=?,updated_at=?
                WHERE id=? AND subowner_payout_status='processing'
                """,
                (payout_id, now_iso(), now_iso(), int(oid)),
            )
            con.commit()
        finally:
            con.close()
        print(
            f"[AFILIADO] pedido=#{oid} terceiro_repasse=paid "
            f"destino={mask_split_email(email)} valor={money(amount)} id={payout_id or '-'}",
            flush=True,
        )
        return True, "terceiro repasse realizado"
    except Exception as exc:
        error = str(exc)[:800]
        con = db()
        try:
            con.execute(
                """
                UPDATE orders
                SET subowner_payout_status='failed',subowner_payout_error=?,updated_at=?
                WHERE id=? AND subowner_payout_status='processing'
                """,
                (error, now_iso(), int(oid)),
            )
            con.commit()
        finally:
            con.close()
        print(f"[AFILIADO] pedido=#{oid} terceiro_repasse=failed erro={error}", flush=True)
        return False, error


async def verify(oid, force=False):
    o = get_order(oid)
    if not o:
        return False, "Pedido não encontrado."
    if o["status"] == "aprovado":
        if not force:
            await process_subowner_payout(oid)
        return True, "✅ Pedido já aprovado."
    if force:
        state = "COMPLETO"
    else:
        try:
            res = await check_pix(o["guild_id"], o["transaction_id"])
            tr = res.get("transaction") or res.get("data") or {}
            state = str(tr.get("transactionState") or tr.get("status") or "").upper()
        except Exception as ex:
            return False, f"❌ Erro ao consultar: `{str(ex)[:220]}`"
    if state != "COMPLETO":
        return False, f"🟡 Ainda aguardando. Status: **{state or 'PENDENTE'}**."
    con = db()
    cur = con.cursor()
    current = cur.execute(
        "SELECT * FROM orders WHERE id=? FOR UPDATE", (oid,)
    ).fetchone()
    if current["status"] == "aprovado":
        con.close()
        return True, "✅ Já processado."
    cur.execute(
        "UPDATE orders SET status='aprovado',paid_at=?,updated_at=?,is_test=? WHERE id=?",
        (now_iso(), now_iso(), 1 if force else current["is_test"], oid),
    )
    if not force:
        cur.execute(
            "UPDATE products SET stock=CASE WHEN stock>0 THEN stock-1 ELSE stock END WHERE id=?",
            (current["product_id"],),
        )
    con.commit()
    con.close()
    if not force:
        await process_subowner_payout(oid)
    await deliver(oid)
    return True, "✅ Pagamento confirmado! Entrega enviada no privado."


async def sale_card(member, o):
    W, H = 760, 410
    img = Image.new("RGB", (W, H), (8, 9, 12))
    d = ImageDraw.Draw(img)

    regular_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

    f_small = ImageFont.truetype(regular_path, 15)
    f_regular = ImageFont.truetype(regular_path, 18)
    f_bold = ImageFont.truetype(bold_path, 20)
    f_title = ImageFont.truetype(bold_path, 24)
    f_status = ImageFont.truetype(bold_path, 27)
    f_value = ImageFont.truetype(bold_path, 28)

    # Card principal
    left, top, right, bottom = 22, 18, W - 22, H - 18
    d.rounded_rectangle(
        (left, top, right, bottom),
        radius=20,
        fill=(22, 24, 29),
        outline=(70, 74, 84),
        width=2,
    )

    # Avatar
    avatar_x, avatar_y, avatar_size = 46, 42, 78
    try:
        async with aiohttp.ClientSession() as sess:
            async with sess.get(member.display_avatar.url) as response:
                avatar_data = await response.read()
        avatar = (
            Image.open(io.BytesIO(avatar_data))
            .convert("RGB")
            .resize((avatar_size, avatar_size))
        )
        mask = Image.new("L", (avatar_size, avatar_size), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, avatar_size, avatar_size), fill=255)
        img.paste(avatar, (avatar_x, avatar_y), mask)
    except Exception:
        d.ellipse(
            (avatar_x, avatar_y, avatar_x + avatar_size, avatar_y + avatar_size),
            fill=(139, 44, 245),
        )

    # Cabeçalho
    display_name = str(member.display_name)[:24]
    username = f"@{member.name}"[:30]
    d.text((145, 45), display_name, font=f_title, fill=(245, 246, 250))
    d.text((145, 80), username, font=f_regular, fill=(150, 155, 166))

    # Data/hora no topo direito
    stamp = datetime.now(timezone.utc).astimezone().strftime("%d/%m • %H:%M")
    stamp_bbox = d.textbbox((0, 0), stamp, font=f_small)
    stamp_w = stamp_bbox[2] - stamp_bbox[0]
    d.text((right - 28 - stamp_w, 50), stamp, font=f_small, fill=(145, 150, 160))

    # Status
    d.text((48, 142), "✓", font=f_status, fill=(40, 220, 115))
    d.text((86, 142), "Compra Realizada", font=f_status, fill=(40, 220, 115))

    # Separador 1
    d.line((46, 188, right - 28, 188), fill=(62, 66, 76), width=2)

    # Produto
    d.text((48, 207), "Carrinho", font=f_small, fill=(145, 150, 160))
    product_name = f"{o['product_name']} x1"
    if len(product_name) > 34:
        product_name = product_name[:31] + "..."
    d.text((48, 238), product_name, font=f_bold, fill=(245, 246, 250))

    price_text = money(o["amount"])
    price_bbox = d.textbbox((0, 0), price_text, font=f_bold)
    price_w = price_bbox[2] - price_bbox[0]
    d.text((right - 28 - price_w, 238), price_text, font=f_bold, fill=(245, 246, 250))

    # Separador 2
    d.line((46, 282, right - 28, 282), fill=(62, 66, 76), width=2)

    # Valor pago
    d.text((48, 302), "Valor pago", font=f_small, fill=(145, 150, 160))
    value_text = money(o["amount"])
    value_bbox = d.textbbox((0, 0), value_text, font=f_value)
    value_w = value_bbox[2] - value_bbox[0]
    d.text((right - 28 - value_w, 300), value_text, font=f_value, fill=(0, 235, 110))

    # Rodapé totalmente dentro do card
    footer_y = 357
    d.line((46, footer_y - 12, right - 28, footer_y - 12), fill=(50, 54, 63), width=1)
    d.text((48, footer_y), "ENTREGAS AUTOMÁTICAS", font=f_small, fill=(200, 170, 255))

    footer_right = STORE_URL.replace("https://", "").replace("http://", "")
    if len(footer_right) > 30:
        footer_right = footer_right[:27] + "..."
    footer_bbox = d.textbbox((0, 0), footer_right, font=f_small)
    footer_w = footer_bbox[2] - footer_bbox[0]
    d.text(
        (right - 28 - footer_w, footer_y),
        footer_right,
        font=f_small,
        fill=(145, 150, 160),
    )

    bio = io.BytesIO()
    img.save(bio, "PNG")
    bio.seek(0)
    return bio


def get_key_products_for_guild(guild_id, limit=25):
    """Produtos do servidor com geração de key ativada."""
    con = db()
    try:
        return con.execute(
            """
            SELECT *
            FROM products
            WHERE guild_id=?
              AND COALESCE(license_enabled,0)=1
            ORDER BY local_id ASC
            LIMIT ?
            """,
            (int(guild_id), int(limit)),
        ).fetchall()
    finally:
        con.close()


class OwnerTestProductSelect(discord.ui.Select):
    def __init__(self, guild_id):
        products = get_key_products_for_guild(guild_id, 25)
        self.products_by_value = {}

        options = []
        for product in products:
            benefits = get_product_benefits(product)
            local_id = int(_row_value(product, "local_id", 0) or 0)
            duration = benefits["duration_days"]
            validity = "Permanente" if duration == 0 else f"{duration} dias"
            app_code = str(_row_value(product, "license_app_code", "") or "").strip()

            value = str(int(product["id"]))
            self.products_by_value[value] = product

            description = validity
            if app_code:
                description += f" • {app_code}"
            description = description[:100]

            options.append(
                discord.SelectOption(
                    label=f"#{local_id} • {str(product['name'])[:80]}",
                    description=description,
                    value=value,
                    emoji="🔑",
                )
            )

        if not options:
            options = [
                discord.SelectOption(
                    label="Nenhum produto com key ativa",
                    description="Configure /keys key-produto primeiro",
                    value="none",
                    emoji="⚠️",
                )
            ]

        super().__init__(
            placeholder="Escolha o produto da key de teste...",
            min_values=1,
            max_values=1,
            options=options,
            custom_id="locksensi:owner:test-product",
        )

    async def callback(self, i: discord.Interaction):
        if int(i.user.id) != LOCKSENSI_OWNER_ID:
            await i.response.send_message(
                "❌ Esta opção de teste é exclusiva do dono.",
                ephemeral=True,
            )
            return

        selected = self.values[0]
        if selected == "none":
            await i.response.send_message(
                "❌ Nenhum produto com geração de key ativada.",
                ephemeral=True,
            )
            return

        product = self.products_by_value.get(selected)
        if not product:
            product = get_product(int(selected))

        if not product or int(product["guild_id"]) != int(i.guild.id):
            await i.response.send_message(
                "❌ Produto não encontrado neste servidor.",
                ephemeral=True,
            )
            return

        try:
            result = create_manual_license(
                product,
                i.guild.id,
                i.user.id,
            )
        except Exception as exc:
            await i.response.send_message(
                f"❌ Não consegui gerar a key de teste: `{str(exc)[:600]}`",
                ephemeral=True,
            )
            return

        benefits = get_product_benefits(product)
        validity = _format_expiry(result["expires_at"])
        hwid_text = "1 PC" if benefits["hwid_required"] else "Desativado"
        app_code = (
            str(_row_value(product, "license_app_code", "") or "").strip()
            or "não vinculado"
        )

        embed = discord.Embed(
            title="🧪 Key de Teste Criada",
            description=(
                f"📦 **Produto:** {product['name']}\n"
                f"⏳ **Validade:** {validity}\n"
                f"💻 **HWID:** {hwid_text}\n"
                f"🔒 **App:** `{app_code}`\n\n"
                "### Key\n"
                f"```{result['license_key']}```\n"
                "Essa key foi criada manualmente para teste do dono."
            ),
            color=0xE31B2B,
        )
        embed.set_footer(
            text=(f"LOCK SENSI • Teste do dono • ID interno {result['order_id']}")
        )

        await i.response.edit_message(
            content=None,
            embed=embed,
            view=OwnerTestAgainView(i.guild.id),
        )


class OwnerTestAgainView(discord.ui.View):
    def __init__(self, guild_id):
        super().__init__(timeout=180)
        self.guild_id = int(guild_id)

    @discord.ui.button(
        label="➕ Gerar outra Key de Teste",
        style=discord.ButtonStyle.primary,
    )
    async def again(
        self,
        i: discord.Interaction,
        button: discord.ui.Button,
    ):
        if int(i.user.id) != LOCKSENSI_OWNER_ID:
            await i.response.send_message(
                "❌ Esta opção é exclusiva do dono.",
                ephemeral=True,
            )
            return

        await i.response.edit_message(
            content="🧪 **Modo teste do dono:** escolha o produto.",
            embed=None,
            view=OwnerTestProductView(self.guild_id),
        )


class OwnerTestProductView(discord.ui.View):
    def __init__(self, guild_id):
        super().__init__(timeout=180)
        self.add_item(OwnerTestProductSelect(guild_id))


class LicenseGenerateView(discord.ui.View):
    """
    Painel público de resgate.
    Qualquer comprador pode clicar; o bot só libera se encontrar
    uma compra APROVADA de um produto com geração de key ativada.
    """

    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="🔑 Criar Key",
        style=discord.ButtonStyle.primary,
        custom_id="locksensi:license:generate",
    )
    async def generate_key(
        self,
        i: discord.Interaction,
        button: discord.ui.Button,
    ):
        if not i.guild:
            await i.response.send_message(
                "❌ Use este botão dentro do servidor.",
                ephemeral=True,
            )
            return

        # DONO: modo de teste ilimitado.
        # Não precisa ter compra aprovada e cada seleção gera uma key nova.
        if int(i.user.id) == LOCKSENSI_OWNER_ID:
            products = get_key_products_for_guild(i.guild.id, 25)
            if not products:
                await i.response.send_message(
                    "❌ Nenhum produto com geração de key ativada neste servidor.",
                    ephemeral=True,
                )
                return

            await i.response.send_message(
                "🧪 **Modo teste do dono**\n"
                "Escolha abaixo qual produto você quer testar. "
                "Você pode gerar quantas keys quiser.",
                view=OwnerTestProductView(i.guild.id),
                ephemeral=True,
            )
            return

        # CLIENTE NORMAL:
        # não usa a permissão de staff; valida a compra do próprio usuário.
        await i.response.defer(ephemeral=True, thinking=True)

        order = await find_license_order_for_user(i.guild.id, i.user.id)
        if not order:
            await i.followup.send(
                "❌ **Nenhuma compra aprovada encontrada.**\n\n"
                "O bot só cria keys de produtos já pagos e aprovados. "
                "Se você acabou de pagar, aguarde a confirmação do pagamento "
                "e clique em **Criar Key** novamente.",
                ephemeral=True,
            )
            return

        product = get_product(int(order["product_id"]))
        benefits = get_product_benefits(product)

        try:
            license_key, created = await get_or_create_order_license(int(order["id"]))
        except Exception as exc:
            await i.followup.send(
                f"❌ Não consegui criar sua key agora.\n`{str(exc)[:700]}`",
                ephemeral=True,
            )
            return

        row = get_generated_key_by_order(int(order["id"]))
        expiry = _format_expiry(_row_value(row, "expires_at"))
        hwid_text = "1 PC" if benefits["hwid_required"] else "Desativado"

        result_embed = discord.Embed(
            title=(
                "🔑 Key criada com sucesso!" if created else "🔑 Sua Key Lock Sensi"
            ),
            description=(
                f"📦 **Produto:** {order['product_name']}\n"
                f"🧾 **Pedido:** `#{order['id']}`\n"
                f"⏳ **Validade:** {expiry}\n"
                f"💻 **HWID:** {hwid_text}\n\n"
                "### Sua Key\n"
                f"```{license_key}```\n"
                "Copie a key acima e cole na tela de acesso do seu produto."
            ),
            color=0xE31B2B,
        )
        result_embed.set_footer(
            text=("LOCK SENSI • A mesma compra sempre retorna a mesma key")
        )

        # Mostra para copiar imediatamente no Discord.
        await i.followup.send(
            embed=result_embed,
            ephemeral=True,
        )

        # E envia a mesma key na DM.
        try:
            dm_embed = discord.Embed(
                title="🔐 Sua Key • Lock Sensi",
                description=(
                    f"✅ Sua key de **{order['product_name']}** está pronta.\n\n"
                    f"⏳ **Validade:** {expiry}\n"
                    f"💻 **HWID:** {hwid_text}\n\n"
                    f"```{license_key}```\n"
                    "Guarde esta mensagem. Se você clicar no painel novamente, "
                    "o bot mostrará a mesma key desta compra."
                ),
                color=0xE31B2B,
            )
            dm_embed.set_footer(text=f"Pedido #{order['id']} • LOCK SENSI")
            await i.user.send(embed=dm_embed)
        except Exception:
            # DM fechada não impede o resgate: a key já apareceu ephemeral.
            pass


class SaleView(discord.ui.View):
    def __init__(self, guild_id):
        super().__init__(timeout=None)

        cfg = get_cfg(guild_id)
        store_url = None
        feedback_url = None

        if cfg:
            try:
                store_url = cfg["store_url"]
            except Exception:
                store_url = None

            try:
                feedback_url = cfg["feedback_url"]
            except Exception:
                feedback_url = None

        # Nenhum fallback para o antigo Renegade.
        # O botão Comprar só aparece se ESTE servidor configurar seu próprio link.
        if valid_url(store_url):
            self.add_item(
                discord.ui.Button(
                    label="🛒 Comprar",
                    url=str(store_url).strip(),
                )
            )

        if valid_url(feedback_url):
            self.add_item(
                discord.ui.Button(
                    label="🏆 Ver Feedbacks",
                    url=str(feedback_url).strip(),
                )
            )


async def deliver(oid):
    o = get_order(oid)
    p = get_product(o["product_id"])
    guild = BOT.get_guild(o["guild_id"])
    member = guild.get_member(o["user_id"]) if guild else None
    if guild and not member:
        try:
            member = await guild.fetch_member(o["user_id"])
        except Exception:
            member = None

    dm_user = member
    if not dm_user:
        try:
            dm_user = await BOT.fetch_user(o["user_id"])
        except Exception:
            dm_user = None

    role_result = None
    if guild and isinstance(member, discord.Member):
        role_result = await grant_purchase_role(guild, member, p)

    benefits = get_product_benefits(p)

    # A key não é criada aqui.
    # O cliente cria a própria key pelo painel "Criar sua Key" depois
    # que esta compra já estiver aprovada.
    sent = False
    if dm_user:
        e = discord.Embed(
            title="✅ Compra aprovada e entregue",
            description=f"Produto: **{o['product_name']}**\nPedido: `#{oid}`",
            color=0x39D98A,
        )
        e.add_field(
            name="📦 Dados da entrega",
            value=f"```{(p['delivery_text'] or 'Abra um ticket para receber sua entrega.')[:1000]}```",
            inline=False,
        )

        if benefits["license_enabled"]:
            e.add_field(
                name="🔑 Criar sua Key",
                value=(
                    "Sua compra já está **liberada para resgate**.\n"
                    "Vá até o painel de keys do servidor e clique em "
                    "**🔑 Criar Key**.\n\n"
                    "O bot identifica automaticamente o produto e a validade "
                    "que você comprou."
                ),
                inline=False,
            )

        if role_result:
            e.add_field(
                name="🎭 Cargo da compra",
                value=role_result[:1000],
                inline=False,
            )

        try:
            await dm_user.send(embed=e)
            sent = True
        except Exception:
            pass
    cfg = get_cfg(o["guild_id"])
    ch = None
    if guild and cfg:
        # Primeiro tenta os IDs salvos no banco.
        for channel_id in (
            cfg["log_channel_id"],
            cfg["purchase_channel_id"],
            cfg["sales_channel_id"],
        ):
            if not channel_id:
                continue
            candidate = guild.get_channel(int(channel_id))
            if isinstance(candidate, discord.TextChannel):
                ch = candidate
                break

        # Após migração, IDs antigos podem apontar para canais que não existem mais.
        # Nesse caso, procura automaticamente um canal de logs pelo nome atual.
        if ch is None:
            preferred_names = {
                "logs-vendas",
                "log-vendas",
                "vendas-realizadas",
                "logs-de-vendas",
            }
            for candidate in guild.text_channels:
                normalized = candidate.name.lower().replace("・", "-").replace(" ", "-")
                if (
                    normalized in preferred_names
                    or "logs-vendas" in normalized
                    or ("log" in normalized and "venda" in normalized)
                ):
                    ch = candidate
                    break

            # Salva o novo ID para as próximas vendas.
            if ch is not None:
                try:
                    con = db()
                    con.execute(
                        "UPDATE guild_config SET log_channel_id=? WHERE guild_id=?",
                        (ch.id, o["guild_id"]),
                    )
                    con.commit()
                    con.close()
                    print(
                        f"Canal de logs atualizado automaticamente para #{ch.name} ({ch.id})."
                    )
                except Exception as exc:
                    print(f"Não consegui salvar o novo canal de logs: {exc}")

    if ch and member:
        try:
            await ch.send(
                file=discord.File(
                    await sale_card(member, o), filename=f"venda-{oid}.png"
                ),
                view=SaleView(o["guild_id"]),
            )
            if _row_value(o, "affiliate_id"):
                affiliate_log = discord.Embed(
                    title="🤝 Venda atribuída a afiliado",
                    description=(
                        f"🧾 Pedido: `#{oid}`\n"
                        f"🛒 Comprador: {member.mention}\n"
                        f"📣 Afiliado: <@{o['affiliate_user_id']}> "
                        f"(**{o['affiliate_name']}**)\n"
                        f"💸 Comissão: **{float(o['affiliate_percent'] or 0):g}%** "
                        f"({money(o['affiliate_amount'])})\n"
                        + (
                            f"👑 Subdono: **{float(o['subowner_percent'] or 0):g}%** "
                            f"({money(o['subowner_amount'])}) • "
                            f"status `{o['subowner_payout_status']}`"
                            if float(_row_value(o, "subowner_amount", 0) or 0) > 0
                            else "👑 Subdono: **não usado nesta venda**"
                        )
                    ),
                    color=0xE31B2B,
                )
                await ch.send(embed=affiliate_log)
        except Exception as exc:
            print(f"Erro ao enviar card da venda #{oid}: {exc}")
    elif guild:
        print(
            f"Canal de logs da venda #{oid} não encontrado. "
            f"Confira log_channel_id/purchase_channel_id/sales_channel_id."
        )
    con = db()
    con.execute("UPDATE orders SET delivered=? WHERE id=?", (1 if sent else 0, oid))
    con.commit()
    con.close()
    if guild and o["cart_channel_id"]:
        cc = guild.get_channel(o["cart_channel_id"])
        if cc:
            try:
                await cc.send(
                    "✅ Pagamento aprovado. A entrega foi enviada no seu privado. Este carrinho fechará em 20 segundos."
                )
                await asyncio.sleep(20)
                clear_cart_coupon(cc.id)
                clear_cart_affiliate(cc.id)
                await cc.delete()
            except:
                pass


async def watcher():
    await BOT.wait_until_ready()
    while not BOT.is_closed():
        try:
            con = db()
            rows = con.execute(
                "SELECT id FROM orders WHERE status='pendente' AND transaction_id!='' ORDER BY id DESC LIMIT 30"
            ).fetchall()
            con.close()
            for r in rows:
                await verify(r["id"])
                await asyncio.sleep(1.05)

            # Se o processo reiniciar no meio de um repasse, libera o claim
            # antigo e tenta novamente. Cada pedido tem no máximo 5 tentativas.
            con = db()
            con.execute(
                """
                UPDATE orders
                SET subowner_payout_status='failed',
                    subowner_payout_error='Processamento interrompido; nova tentativa agendada'
                WHERE subowner_payout_status='processing'
                  AND updated_at < NOW() - INTERVAL '10 minutes'
                """
            )
            payout_rows = con.execute(
                """
                SELECT id FROM orders
                WHERE status='aprovado'
                  AND subowner_payout_status IN ('pending','failed')
                  AND COALESCE(subowner_payout_attempts,0)<5
                ORDER BY id ASC
                LIMIT 20
                """
            ).fetchall()
            con.commit()
            con.close()
            for r in payout_rows:
                await process_subowner_payout(r["id"])
                await asyncio.sleep(1.05)
        except Exception as e:
            print("Mistic watcher:", e)
        await asyncio.sleep(25)


class MisticPayConfigModal(discord.ui.Modal, title="Conectar MisticPay"):
    client_id = discord.ui.TextInput(
        label="Client ID",
        placeholder="Cole o Client ID da sua conta MisticPay",
        min_length=5,
        max_length=300,
    )
    client_secret = discord.ui.TextInput(
        label="Client Secret",
        placeholder="Cole o Client Secret da sua conta MisticPay",
        min_length=5,
        max_length=500,
        style=discord.TextStyle.paragraph,
    )

    async def on_submit(self, interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(interaction):
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        client_id = str(self.client_id).strip()
        client_secret = str(self.client_secret).strip()

        try:
            account = await test_mistic_credentials(client_id, client_secret)
            save_mistic_credentials(
                interaction.guild.id,
                client_id,
                client_secret,
                account,
            )
            await interaction.followup.send(
                "✅ MisticPay conectada com sucesso.\n"
                f"Conta: **{account.get('name') or 'não informado'}**\n"
                "As próximas cobranças deste servidor serão criadas nessa conta.",
                ephemeral=True,
            )
        except Exception as error:
            await interaction.followup.send(
                f"❌ Não foi possível conectar: `{str(error)[:700]}`",
                ephemeral=True,
            )


class MisticPayCommands(app_commands.Group):
    def __init__(self):
        super().__init__(
            name="misticpay",
            description="Conecta a MisticPay deste servidor",
        )

    @app_commands.command(
        name="configurar",
        description="Conecta a conta MisticPay deste servidor",
    )
    async def configure(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        if not FERNET_KEY:
            await i.response.send_message(
                "❌ O dono do bot ainda não configurou MISTICPAY_FERNET_KEY no Replit.",
                ephemeral=True,
            )
            return
        await i.response.send_modal(MisticPayConfigModal())

    @app_commands.command(
        name="status",
        description="Mostra qual conta MisticPay está conectada",
    )
    async def status(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        row = get_mistic_row(i.guild.id)
        if not row or int(row["active"] or 0) != 1:
            fallback = ""
            if CI and CS:
                fallback = "\n⚠️ Este servidor está usando a conta global do bot."
            await i.response.send_message(
                "❌ Nenhuma conta própria conectada." + fallback,
                ephemeral=True,
            )
            return

        await i.response.send_message(
            "✅ MisticPay própria conectada.\n"
            f"Conta: **{row['account_name'] or 'não informado'}**\n"
            f"E-mail: `{mask_value(row['account_email'], 3)}`\n"
            f"Client ID: `{mask_value(decrypt_secret(row['client_id_enc']), 5)}`",
            ephemeral=True,
        )

    @app_commands.command(
        name="testar",
        description="Testa a conexão MisticPay salva",
    )
    async def test(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        await i.response.defer(ephemeral=True, thinking=True)
        try:
            client_id, client_secret, source = get_mistic_credentials(
                i.guild.id,
                allow_global=False,
            )
            account = await test_mistic_credentials(client_id, client_secret)
            balance = await api(
                "GET",
                "/users/balance",
                credentials=(client_id, client_secret),
            )
            balance_data = balance.get("data") or {}
            await i.followup.send(
                "✅ Conexão funcionando.\n"
                f"Conta: **{account.get('name') or 'não informado'}**\n"
                f"Verificada: `{account.get('accountVerified')}`\n"
                f"Saldo: **{money(balance_data.get('balance', balance_data.get('availableBalance', 0)))}**",
                ephemeral=True,
            )
        except Exception as error:
            await i.followup.send(
                f"❌ Falha no teste: `{str(error)[:700]}`",
                ephemeral=True,
            )

    @app_commands.command(
        name="desconectar",
        description="Remove a conta MisticPay deste servidor",
    )
    async def disconnect(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        con = db()
        con.execute(
            "UPDATE guild_misticpay_credentials SET active=0, updated_at=? WHERE guild_id=?",
            (now_iso(), i.guild.id),
        )
        con.commit()
        con.close()
        await i.response.send_message(
            "✅ MisticPay desconectada deste servidor.",
            ephemeral=True,
        )


def can_manually_generate_locksensi_key(interaction):
    """Owner específico OU membro com um dos dois cargos autorizados."""
    user = getattr(interaction, "user", None)
    if not user:
        return False

    if int(user.id) == LOCKSENSI_OWNER_ID:
        return True

    roles = getattr(user, "roles", None) or []
    return any(
        int(getattr(role, "id", 0)) in LOCKSENSI_KEY_STAFF_ROLE_IDS for role in roles
    )


async def require_manual_key_permission(interaction):
    if can_manually_generate_locksensi_key(interaction):
        return True

    if interaction.response.is_done():
        await interaction.followup.send(
            "❌ Você não possui permissão para gerar keys manualmente.",
            ephemeral=True,
        )
    else:
        await interaction.response.send_message(
            "❌ Você não possui permissão para gerar keys manualmente.",
            ephemeral=True,
        )
    return False


def create_manual_license(product, guild_id, user_id, duration_hours=None):
    """
    Cria uma key sem compra/pedido.
    Usa um order_id NEGATIVO reservado para geração manual.
    """
    benefits = get_product_benefits(product)
    if not benefits["license_enabled"]:
        raise RuntimeError("Este produto não está com geração de keys ativada.")

    license_key = create_unique_license(benefits["prefix"])
    if duration_hours is None:
        expires_at = _build_expiry(benefits["duration_days"])
    else:
        duration_hours = int(duration_hours)
        if duration_hours < 1 or duration_hours > 24 * 36500:
            raise ValueError("Use entre 1 e 876000 horas.")
        expires_at = _build_expiry_hours(duration_hours)

    # Negativo para nunca colidir com IDs normais de pedidos.
    # Faz algumas tentativas em caso de concorrência extrema.
    for _ in range(20):
        manual_order_id = -int(time.time_ns() // 1000)
        con = db()
        try:
            try:
                con.execute(
                    """
                    INSERT INTO generated_keys(
                        guild_id,user_id,product_id,order_id,license_key,
                        status,expires_at,created_at,updated_at
                    )
                    VALUES(?,?,?,?,?,'active',?,?,?)
                    """,
                    (
                        int(guild_id),
                        int(user_id),
                        int(product["id"]),
                        int(manual_order_id),
                        license_key,
                        expires_at,
                        now_iso(),
                        now_iso(),
                    ),
                )
                con.commit()
                return {
                    "license_key": license_key,
                    "expires_at": expires_at,
                    "order_id": manual_order_id,
                }
            except Exception as exc:
                con.rollback()
                # Em uma colisão raríssima, gera outro ID/key e tenta novamente.
                lowered = str(exc).lower()
                if "unique" not in lowered and "duplicate" not in lowered:
                    raise
                license_key = create_unique_license(benefits["prefix"])
                time.sleep(0.001)
        finally:
            con.close()

    raise RuntimeError("Não consegui criar uma key manual única.")


class LockSensiKeysCommands(app_commands.Group):
    def __init__(self):
        super().__init__(
            name="keys",
            description="Keys, HWID e benefícios Lock Sensi",
        )

    @app_commands.command(
        name="gerar-key",
        description="Gera manualmente uma key Lock Sensi para um produto",
    )
    @app_commands.describe(
        produto_id="ID local do produto mostrado em /loja produtos",
        usuario="Cliente que será dono da key (opcional)",
        horas="Validade desta key em horas. Ex: 1, 6, 12 ou 24",
    )
    async def generate_manual_key(
        self,
        i: discord.Interaction,
        produto_id: int,
        usuario: Optional[discord.Member] = None,
        horas: Optional[int] = None,
    ):
        # Esta permissão é propositalmente independente do ADMIN_CHECK:
        # só os dois cargos definidos acima OU o owner podem gerar key manual.
        if not await require_manual_key_permission(i):
            return

        if not i.guild:
            await i.response.send_message(
                "❌ Use este comando dentro de um servidor.",
                ephemeral=True,
            )
            return

        product, _state = resolve_product_for_guild(
            produto_id,
            i.guild.id,
            repair=False,
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.",
                ephemeral=True,
            )
            return

        benefits = get_product_benefits(product)
        if not benefits["license_enabled"]:
            await i.response.send_message(
                "❌ Esse produto ainda não possui geração de key ativada.\n"
                "Configure primeiro com `/keys key-produto`.",
                ephemeral=True,
            )
            return

        target = usuario or i.user
        try:
            result = create_manual_license(
                product,
                i.guild.id,
                target.id,
                duration_hours=horas,
            )
        except Exception as exc:
            await i.response.send_message(
                f"❌ Não consegui gerar a key: `{str(exc)[:600]}`",
                ephemeral=True,
            )
            return

        validade = _format_expiry(result["expires_at"])
        app_code = (
            str(_row_value(product, "license_app_code", "") or "").strip()
            or "não vinculado"
        )

        embed = discord.Embed(
            title="🔑 Key Lock Sensi gerada",
            description=(
                f"📦 Produto: **{product['name']}** (`#{produto_id}`)\n"
                f"👤 Cliente: {target.mention} (`{target.id}`)\n"
                f"⏳ Validade: **{validade}**\n"
                f"🕐 Duração escolhida: **{str(horas) + ' hora(s)' if horas else 'padrão do produto'}**\n"
                f"💻 HWID: **{'1 PC' if benefits['hwid_required'] else 'desativado'}**\n"
                f"🔒 App: `{app_code}`\n\n"
                f"**Key:**\n```{result['license_key']}```"
            ),
            color=0xE53945,
        )
        embed.set_footer(
            text=f"Geração manual • por {i.user} • ID interno {result['order_id']}"
        )

        await i.response.send_message(embed=embed, ephemeral=True)

        # Se você escolheu um cliente, tenta entregar a key na DM dele também.
        if usuario is not None:
            try:
                dm_embed = discord.Embed(
                    title="🔑 Sua Key Lock Sensi",
                    description=(
                        f"📦 Produto: **{product['name']}**\n"
                        f"⏳ Validade: **{validade}**\n\n"
                        f"```{result['license_key']}```\n"
                        "Guarde sua key em um local seguro."
                    ),
                    color=0xE53945,
                )
                await usuario.send(embed=dm_embed)
            except Exception:
                pass

    @app_commands.command(
        name="key-produto",
        description="Ativa o sistema GRATUITO de keys Lock Sensi em um produto",
    )
    @app_commands.describe(
        produto_id="ID local mostrado em /loja produtos",
        dias="Validade em dias. Use 0 para permanente",
        prefixo="Início da key. Ex: LOCK, LS, PRO",
        hwid="Se a key deve ficar presa ao primeiro PC/HWID validado",
    )
    async def license_product(
        self,
        i: discord.Interaction,
        produto_id: int,
        dias: int = 30,
        prefixo: str = "LOCK",
        hwid: bool = True,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id,
            i.guild.id,
            repair=False,
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.\n"
                "Use `/loja produtos` para conferir os IDs.",
                ephemeral=True,
            )
            return

        dias = int(dias)
        if dias < 0 or dias > 36500:
            await i.response.send_message(
                "❌ `dias` precisa ficar entre **0 e 36500**. Use `0` para permanente.",
                ephemeral=True,
            )
            return

        prefixo = normalize_license_prefix(prefixo)

        con = db()
        try:
            con.execute(
                """
                UPDATE products
                SET license_enabled=1,
                    license_duration_days=?,
                    license_prefix=?,
                    license_hwid_required=?
                WHERE id=? AND guild_id=?
                """,
                (
                    dias,
                    prefixo,
                    1 if hwid else 0,
                    int(product["id"]),
                    i.guild.id,
                ),
            )
            con.commit()
        finally:
            con.close()

        validade = "Permanente" if dias == 0 else f"{dias} dia(s)"
        await i.response.send_message(
            "✅ **Sistema de keys ativado neste produto.**\n"
            f"📦 Produto: **{product['name']}** (`#{produto_id}`)\n"
            f"🔑 Prefixo: `{prefixo}`\n"
            f"⏳ Validade: **{validade}**\n"
            f"💻 HWID: **{'1 PC' if hwid else 'desativado'}**\n\n"
            "Após a compra ser aprovada, o bot gera a key no **Supabase**, "
            "usando o sistema próprio gratuito do Supabase.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-app",
        description="Vincula um produto a um painel/app Lock Sensi específico",
    )
    @app_commands.describe(
        produto_id="ID local mostrado em /loja produtos",
        app_code="Código do painel. Ex: LOCKSENSI_PRO_V27",
    )
    async def license_app(self, i: discord.Interaction, produto_id: int, app_code: str):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id, i.guild.id, repair=False
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado.",
                ephemeral=True,
            )
            return

        app_code = re.sub(r"[^A-Za-z0-9_-]", "", str(app_code or "")).upper()[:80]
        if not app_code:
            await i.response.send_message(
                "❌ Informe um app_code válido.", ephemeral=True
            )
            return

        con = db()
        try:
            con.execute(
                "UPDATE products SET license_app_code=? WHERE id=? AND guild_id=?",
                (app_code, int(product["id"]), i.guild.id),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            "✅ **Produto vinculado ao painel.**\n"
            f"📦 {product['name']} (`#{produto_id}`)\n"
            f"🔐 App code: `{app_code}`\n\n"
            "Keys deste produto só serão aceitas pelo painel com esse mesmo código.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-app-remover",
        description="Remove o vínculo de app/painel de um produto",
    )
    async def license_app_remove(self, i: discord.Interaction, produto_id: int):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id, i.guild.id, repair=False
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            con.execute(
                "UPDATE products SET license_app_code=NULL WHERE id=? AND guild_id=?",
                (int(product["id"]), i.guild.id),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"✅ Vínculo de app removido de **{product['name']}**.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-remover",
        description="Desativa geração de keys em um produto",
    )
    async def license_remove(
        self,
        i: discord.Interaction,
        produto_id: int,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id,
            i.guild.id,
            repair=False,
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            con.execute(
                "UPDATE products SET license_enabled=0 WHERE id=? AND guild_id=?",
                (int(product["id"]), i.guild.id),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"✅ Geração de keys desativada em **{product['name']}**.",
            ephemeral=True,
        )

    @app_commands.command(
        name="produto-cargo",
        description="Define o cargo entregue após comprar um produto",
    )
    @app_commands.describe(
        produto_id="ID local mostrado em /loja produtos",
        cargo="Cargo que será entregue após o pagamento aprovado",
    )
    async def product_role(
        self,
        i: discord.Interaction,
        produto_id: int,
        cargo: discord.Role,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id,
            i.guild.id,
            repair=False,
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            con.execute(
                "UPDATE products SET purchase_role_id=? WHERE id=? AND guild_id=?",
                (cargo.id, int(product["id"]), i.guild.id),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            "✅ **Cargo pós-compra configurado.**\n"
            f"📦 Produto: **{product['name']}** (`#{produto_id}`)\n"
            f"🎭 Cargo: {cargo.mention}\n\n"
            "O cargo do bot precisa ficar acima deste cargo na hierarquia.",
            ephemeral=True,
        )

    @app_commands.command(
        name="produto-cargo-remover",
        description="Remove o cargo automático de um produto",
    )
    async def product_role_remove(
        self,
        i: discord.Interaction,
        produto_id: int,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id,
            i.guild.id,
            repair=False,
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            con.execute(
                "UPDATE products SET purchase_role_id=NULL WHERE id=? AND guild_id=?",
                (int(product["id"]), i.guild.id),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"✅ Cargo automático removido de **{product['name']}**.",
            ephemeral=True,
        )

    @app_commands.command(
        name="produto-beneficios",
        description="Mostra key e cargo configurados em um produto",
    )
    async def product_benefits(
        self,
        i: discord.Interaction,
        produto_id: int,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id,
            i.guild.id,
            repair=False,
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado.",
                ephemeral=True,
            )
            return

        benefits = get_product_benefits(product)
        role = i.guild.get_role(benefits["role_id"]) if benefits["role_id"] else None
        validade = (
            "Permanente"
            if benefits["duration_days"] == 0
            else f"{benefits['duration_days']} dia(s)"
        )

        role_text = "**nenhum**"
        if role:
            role_text = role.mention
        elif benefits["role_id"]:
            role_text = f"`{benefits['role_id']}` (não encontrado)"

        await i.response.send_message(
            "🎁 **Benefícios do produto**\n"
            f"📦 **{product['name']}** (`#{produto_id}`)\n\n"
            f"🎭 Cargo: {role_text}\n"
            f"🔑 Key: **{'ATIVA' if benefits['license_enabled'] else 'DESATIVADA'}**\n"
            f"⏳ Validade: **{validade}**\n"
            f"🏷️ Prefixo: `{benefits['prefix']}`\n"
            f"💻 HWID: **{'1 PC' if benefits['hwid_required'] else 'desativado'}**\n"
            f"🔒 Painel/App: **{benefits['app_code'] or 'qualquer Lock Sensi'}**",
            ephemeral=True,
        )

    @app_commands.command(
        name="painel-keys",
        description="Publica o painel Criar sua Key para compradores",
    )
    @app_commands.describe(canal="Canal onde o painel de resgate será publicado")
    async def license_panel(
        self,
        i: discord.Interaction,
        canal: Optional[discord.TextChannel] = None,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        canal = canal or i.channel

        embed = discord.Embed(
            title="🔐 Criar sua Key",
            description=(
                "Está pronto para começar? Crie sua key do produto "
                "**Lock Sensi** que você comprou.\n\n"
                "### Importante\n"
                "• Você precisa ter uma **compra aprovada** neste servidor.\n"
                "• O bot identifica automaticamente se você comprou "
                "**30 dias, 90 dias ou Permanente**.\n"
                "• Cada compra gera **uma única key**.\n"
                "• Se a key já existir, o bot entrega **a mesma key** novamente.\n"
                "• Depois de criada, sua key aparece para copiar e também "
                "é enviada na sua **DM**.\n"
                "• Produtos com HWID ficam vinculados ao primeiro PC "
                "que ativar a key."
            ),
            color=0xE31B2B,
        )

        # Dá um visual parecido com o card de referência sem depender
        # de imagem externa obrigatória.
        if i.guild and i.guild.icon:
            try:
                embed.set_thumbnail(url=i.guild.icon.url)
            except Exception:
                pass

        embed.add_field(
            name="Pronto para começar?",
            value="Clique no botão abaixo para gerar sua key.",
            inline=False,
        )
        embed.set_footer(text="LOCK SENSI • Sistema automático de resgate")

        await canal.send(
            embed=embed,
            view=LicenseGenerateView(),
        )
        await i.response.send_message(
            f"✅ Painel **Criar sua Key** publicado em {canal.mention}.",
            ephemeral=True,
        )

    @app_commands.command(
        name="minhas-keys",
        description="Mostra suas keys Lock Sensi deste servidor",
    )
    async def my_licenses(self, i: discord.Interaction):
        con = db()
        try:
            rows = con.execute(
                """
                SELECT g.*,p.name AS product_name
                FROM generated_keys g
                LEFT JOIN products p ON p.id=g.product_id
                WHERE g.guild_id=? AND g.user_id=?
                ORDER BY g.id DESC
                LIMIT 20
                """,
                (i.guild.id, i.user.id),
            ).fetchall()
        finally:
            con.close()

        if not rows:
            await i.response.send_message(
                "🔑 Você ainda não possui keys neste servidor.",
                ephemeral=True,
            )
            return

        lines = []
        for row in rows:
            status = effective_key_status(row)
            icon = (
                "✅" if status == "active" else ("⏰" if status == "expired" else "⛔")
            )
            lines.append(
                f"{icon} **{_row_value(row, 'product_name', 'Produto')}**\n"
                f"`{row['license_key']}`\n"
                f"Validade: **{_format_expiry(row['expires_at'])}**"
            )

        await i.response.send_message(
            embed=discord.Embed(
                title="🔑 Suas Keys Lock Sensi",
                description="\n\n".join(lines)[:4000],
                color=0xE53945,
            ),
            ephemeral=True,
        )

    @app_commands.command(
        name="key-consultar",
        description="Consulta uma key Lock Sensi",
    )
    async def license_lookup(
        self,
        i: discord.Interaction,
        chave: str,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        row = get_generated_key(chave, i.guild.id)
        if not row:
            await i.response.send_message(
                "❌ Key não encontrada neste servidor.",
                ephemeral=True,
            )
            return

        product = get_product(row["product_id"])
        status = effective_key_status(row)
        hwid = str(row["hwid"] or "").strip()

        await i.response.send_message(
            "🔎 **Consulta da Key**\n"
            f"🔑 `{row['license_key']}`\n"
            f"📦 Produto: **{product['name'] if product else row['product_id']}**\n"
            f"👤 Usuário: <@{row['user_id']}> (`{row['user_id']}`)\n"
            f"🧾 Pedido: `#{row['order_id']}`\n"
            f"📌 Status: **{status.upper()}**\n"
            f"⏳ Validade: **{_format_expiry(row['expires_at'])}**\n"
            f"💻 HWID: `{hwid if hwid else 'ainda não vinculado'}`",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-revogar",
        description="Bloqueia/revoga uma key",
    )
    async def license_revoke(
        self,
        i: discord.Interaction,
        chave: str,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        row = get_generated_key(chave, i.guild.id)
        if not row:
            await i.response.send_message("❌ Key não encontrada.", ephemeral=True)
            return

        con = db()
        try:
            con.execute(
                "UPDATE generated_keys SET status='revoked',updated_at=? WHERE id=?",
                (now_iso(), int(row["id"])),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"⛔ Key `{row['license_key']}` revogada.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-ativar",
        description="Reativa uma key revogada",
    )
    async def license_activate(
        self,
        i: discord.Interaction,
        chave: str,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        row = get_generated_key(chave, i.guild.id)
        if not row:
            await i.response.send_message("❌ Key não encontrada.", ephemeral=True)
            return

        if effective_key_status(row) == "expired":
            await i.response.send_message(
                "⚠️ Essa key está expirada. Use `/keys key-renovar`.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            con.execute(
                "UPDATE generated_keys SET status='active',updated_at=? WHERE id=?",
                (now_iso(), int(row["id"])),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"✅ Key `{row['license_key']}` reativada.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-renovar",
        description="Renova a validade de uma key",
    )
    @app_commands.describe(
        dias="Dias a partir de agora. Use 0 para permanente",
    )
    async def license_renew(
        self,
        i: discord.Interaction,
        chave: str,
        dias: int,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        row = get_generated_key(chave, i.guild.id)
        if not row:
            await i.response.send_message("❌ Key não encontrada.", ephemeral=True)
            return

        dias = int(dias)
        if dias < 0 or dias > 36500:
            await i.response.send_message(
                "❌ Use entre 0 e 36500 dias.",
                ephemeral=True,
            )
            return

        expires_at = _build_expiry(dias)
        con = db()
        try:
            con.execute(
                """
                UPDATE generated_keys
                SET expires_at=?,status='active',updated_at=?
                WHERE id=?
                """,
                (expires_at, now_iso(), int(row["id"])),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"✅ Key renovada. Nova validade: **{_format_expiry(expires_at)}**.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-hwid-reset",
        description="Desvincula o PC/HWID de uma key",
    )
    async def license_hwid_reset(
        self,
        i: discord.Interaction,
        chave: str,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        row = get_generated_key(chave, i.guild.id)
        if not row:
            await i.response.send_message("❌ Key não encontrada.", ephemeral=True)
            return

        con = db()
        try:
            con.execute(
                """
                UPDATE generated_keys
                SET hwid=NULL,hwid_bound_at=NULL,updated_at=?
                WHERE id=?
                """,
                (now_iso(), int(row["id"])),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"✅ HWID da key `{row['license_key']}` resetado.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-stats",
        description="Mostra estatísticas e espaço usado pelas keys",
    )
    async def license_stats(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        con = db()
        try:
            stats = con.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (
                        WHERE status='active'
                          AND (expires_at IS NULL OR expires_at > NOW())
                    ) AS active_count,
                    COUNT(*) FILTER (
                        WHERE status='revoked'
                    ) AS revoked_count,
                    COUNT(*) FILTER (
                        WHERE expires_at IS NOT NULL
                          AND expires_at <= NOW()
                    ) AS expired_count,
                    COUNT(*) FILTER (
                        WHERE hwid IS NOT NULL AND hwid <> ''
                    ) AS hwid_count
                FROM generated_keys
                WHERE guild_id=?
                """,
                (i.guild.id,),
            ).fetchone()

            try:
                size_row = con._conn.execute(
                    "SELECT pg_total_relation_size('generated_keys')"
                ).fetchone()
                table_bytes = int(size_row[0] or 0) if size_row else 0
            except Exception:
                table_bytes = 0
        finally:
            con.close()

        def human_bytes(n):
            n = float(n or 0)
            for unit in ("B", "KB", "MB", "GB"):
                if n < 1024 or unit == "GB":
                    return f"{n:.1f} {unit}"
                n /= 1024
            return f"{n:.1f} GB"

        await i.response.send_message(
            "📊 **Keys • Estatísticas**\n"
            f"🔑 Total neste servidor: **{int(stats['total'] or 0)}**\n"
            f"✅ Ativas: **{int(stats['active_count'] or 0)}**\n"
            f"⏰ Expiradas: **{int(stats['expired_count'] or 0)}**\n"
            f"⛔ Revogadas: **{int(stats['revoked_count'] or 0)}**\n"
            f"💻 Com HWID vinculado: **{int(stats['hwid_count'] or 0)}**\n"
            f"💾 Tabela `generated_keys`: **{human_bytes(table_bytes)}**\n\n"
            "O tamanho exibido é da tabela inteira do projeto, incluindo outros servidores.",
            ephemeral=True,
        )

    @app_commands.command(
        name="key-limpeza",
        description="Apaga keys revogadas/expiradas antigas para economizar banco",
    )
    @app_commands.describe(
        dias_antigas="Só apaga registros encerrados há pelo menos esta quantidade de dias",
    )
    async def license_cleanup(
        self,
        i: discord.Interaction,
        dias_antigas: int = 90,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        dias_antigas = max(7, min(3650, int(dias_antigas)))

        con = db()
        try:
            cursor = con.execute(
                """
                DELETE FROM generated_keys
                WHERE guild_id=?
                  AND (
                    (
                        status='revoked'
                        AND updated_at < NOW() - (? * INTERVAL '1 day')
                    )
                    OR
                    (
                        expires_at IS NOT NULL
                        AND expires_at < NOW() - (? * INTERVAL '1 day')
                    )
                  )
                """,
                (i.guild.id, dias_antigas, dias_antigas),
            )
            removed = max(0, int(cursor.rowcount or 0))
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            f"🧹 Limpeza concluída: **{removed}** registro(s) removido(s).",
            ephemeral=True,
        )


class CheckoutCommands(app_commands.Group):
    def __init__(self):
        super().__init__(
            name="loja",
            description="Administração da Entregas Automáticas • LinkRoubadão",
        )

    @app_commands.command(
        name="comprar-configurar",
        description="Configura o link do botão Comprar deste servidor",
    )
    @app_commands.describe(
        link="Link da sua loja/site/canal de compra. Ex: https://locksensi.site"
    )
    async def buy_link_configure(
        self,
        i: discord.Interaction,
        link: str,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        link = str(link or "").strip()
        if not valid_url(link):
            await i.response.send_message(
                "❌ Link inválido. Use um endereço começando com `https://` ou `http://`.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            existing = con.execute(
                "SELECT guild_id FROM guild_config WHERE guild_id=?",
                (i.guild.id,),
            ).fetchone()

            if existing:
                con.execute(
                    "UPDATE guild_config SET store_url=? WHERE guild_id=?",
                    (link, i.guild.id),
                )
            else:
                con.execute(
                    "INSERT INTO guild_config(guild_id,store_url) VALUES(?,?)",
                    (i.guild.id, link),
                )

            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            "✅ **Link do botão Comprar configurado!**\n"
            f"🛒 As próximas vendas deste servidor usarão:\n{link}",
            ephemeral=True,
        )

    @app_commands.command(
        name="comprar-status",
        description="Mostra o link atual do botão Comprar",
    )
    async def buy_link_status(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        cfg = get_cfg(i.guild.id)
        link = None
        if cfg:
            try:
                link = cfg["store_url"]
            except Exception:
                link = None

        if valid_url(link):
            await i.response.send_message(
                f"🛒 **Link atual do botão Comprar:**\n{link}",
                ephemeral=True,
            )
        else:
            await i.response.send_message(
                "⚠️ Este servidor ainda não possui link de compra configurado.\n"
                "Use `/loja comprar-configurar`.",
                ephemeral=True,
            )

    @app_commands.command(
        name="comprar-remover",
        description="Remove o link e esconde o botão Comprar",
    )
    async def buy_link_remove(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        con = db()
        try:
            con.execute(
                "UPDATE guild_config SET store_url=NULL WHERE guild_id=?",
                (i.guild.id,),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            "✅ Link de compra removido. "
            "O botão **🛒 Comprar** não aparecerá nas próximas vendas "
            "até você configurar outro link.",
            ephemeral=True,
        )

    @app_commands.command(
        name="feedbacks-configurar",
        description="Configura o link do botão Ver Feedbacks deste servidor",
    )
    @app_commands.describe(
        link="Link do canal/servidor/página de feedbacks. Ex: https://discord.com/channels/..."
    )
    async def feedbacks_configure(
        self,
        i: discord.Interaction,
        link: str,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        link = str(link or "").strip()
        if not valid_url(link):
            await i.response.send_message(
                "❌ Link inválido. Envie um link começando com `https://` ou `http://`.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            # Garante que exista uma linha de configuração para o servidor.
            existing = con.execute(
                "SELECT guild_id FROM guild_config WHERE guild_id=?",
                (i.guild.id,),
            ).fetchone()

            if existing:
                con.execute(
                    "UPDATE guild_config SET feedback_url=? WHERE guild_id=?",
                    (link, i.guild.id),
                )
            else:
                con.execute(
                    "INSERT INTO guild_config(guild_id,feedback_url) VALUES(?,?)",
                    (i.guild.id, link),
                )

            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            "✅ **Link de feedbacks configurado!**\n"
            f"🏆 O botão **Ver Feedbacks** das próximas vendas deste servidor vai abrir:\n"
            f"{link}",
            ephemeral=True,
        )

    @app_commands.command(
        name="feedbacks-remover",
        description="Remove o botão Ver Feedbacks deste servidor",
    )
    async def feedbacks_remove(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        con = db()
        try:
            con.execute(
                "UPDATE guild_config SET feedback_url=NULL WHERE guild_id=?",
                (i.guild.id,),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            "✅ Link de feedbacks removido. O botão **Ver Feedbacks** não aparecerá nas próximas vendas.",
            ephemeral=True,
        )

    @app_commands.command(
        name="feedbacks-status",
        description="Mostra o link de feedbacks configurado neste servidor",
    )
    async def feedbacks_status(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        cfg = get_cfg(i.guild.id)
        link = None
        if cfg:
            try:
                link = cfg["feedback_url"]
            except Exception:
                link = None

        if valid_url(link):
            await i.response.send_message(
                f"🏆 **Feedbacks configurados:**\n{link}",
                ephemeral=True,
            )
        else:
            await i.response.send_message(
                "⚠️ Este servidor ainda não possui link de feedbacks configurado.\n"
                "Use `/loja feedbacks-configurar`.",
                ephemeral=True,
            )

    @app_commands.command(
        name="produto-localizar",
        description="Localiza um produto deste servidor pelo ID local",
    )
    @app_commands.describe(produto_id="ID local do produto mostrado neste servidor")
    async def product_locate(
        self,
        i: discord.Interaction,
        produto_id: int,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id, i.guild.id, repair=False
        )
        if not product:
            await i.response.send_message(
                f"❌ Não existe produto `#{produto_id}` neste servidor.\n"
                "Use `/loja produtos` para ver os IDs corretos deste servidor.",
                ephemeral=True,
            )
            return

        await i.response.send_message(
            "🔎 **Produto localizado**\n"
            f"📦 Nome: **{product['name']}**\n"
            f"🆔 ID deste servidor: `#{product['local_id']}`\n"
            f"💰 Preço: **{money(product['price'])}**\n"
            f"✅ Status: **{'ativo' if product['active'] else 'inativo'}**",
            ephemeral=True,
        )

    @app_commands.command(
        name="split-configurar",
        description="Ativa divisão de pagamento somente em um produto",
    )
    @app_commands.describe(
        produto_id="ID local do produto neste servidor (veja /loja produtos)",
        email="E-mail da outra conta MisticPay que receberá a parte",
        porcentagem="Porcentagem enviada para a outra conta. Ex: 50",
    )
    async def split_configure(
        self,
        i: discord.Interaction,
        produto_id: int,
        email: str,
        porcentagem: float = 50.0,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        try:
            split_user = validate_split_email(email)
        except ValueError:
            await i.response.send_message(
                "❌ Informe o e-mail correto da outra conta MisticPay.",
                ephemeral=True,
            )
            return

        porcentagem = round(float(porcentagem), 2)
        if porcentagem <= 0 or porcentagem >= 100:
            await i.response.send_message(
                "❌ A porcentagem precisa ser maior que 0 e menor que 100.",
                ephemeral=True,
            )
            return

        product, _state = resolve_product_for_guild(
            produto_id, i.guild.id, repair=False
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.\n"
                "Use `/loja produtos` para conferir os IDs locais.",
                ephemeral=True,
            )
            return

        global_product_id = int(product["id"])
        con = db()
        try:
            con.execute(
                """
                UPDATE products
                SET split_enabled=1,split_user=?,split_tax=?,split_override=1
                WHERE id=? AND guild_id=?
                """,
                (split_user, porcentagem, global_product_id, i.guild.id),
            )
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            "✅ **Split individual ativado neste produto.**\n\n"
            f"📦 Produto: **{product['name']}** (`#{produto_id}`)\n"
            f"🏦 MisticPay principal do servidor: **{100 - porcentagem:g}%**\n"
            f"🤝 Outra MisticPay (`{split_user}`): **{porcentagem:g}%**\n\n"
            "Esse override individual tem prioridade sobre regras de grupo. "
            "Os outros produtos permanecem como estavam.",
            ephemeral=True,
        )

    @app_commands.command(
        name="split-remover",
        description="Desativa o split individual de um produto",
    )
    @app_commands.describe(
        produto_id="ID local do produto",
        herdar_grupo="True = volta a herdar um split de grupo que combine com o nome",
    )
    async def split_remove(
        self,
        i: discord.Interaction,
        produto_id: int,
        herdar_grupo: bool = False,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id, i.guild.id, repair=False
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.\n"
                "Use `/loja produtos` para conferir os IDs locais.",
                ephemeral=True,
            )
            return

        global_product_id = int(product["id"])
        con = db()
        try:
            con.execute(
                """
                UPDATE products
                SET split_enabled=0,split_user=NULL,split_tax=0,split_override=?
                WHERE id=? AND guild_id=?
                """,
                (0 if herdar_grupo else 1, global_product_id, i.guild.id),
            )
            con.commit()
        finally:
            con.close()

        refreshed = get_product(global_product_id)
        effective = get_product_split(refreshed)
        if effective:
            detail = (
                f"Agora ele herda o grupo `{effective.get('group')}`: "
                f"**{effective['tax']:g}%** para `{effective['user']}`."
            )
        elif herdar_grupo:
            detail = "Nenhum grupo corresponde ao nome; fica **100% na conta principal**."
        else:
            detail = (
                "Ficou com bloqueio individual: **100% na conta principal**, "
                "mesmo se o nome combinar com algum grupo."
            )

        await i.response.send_message(
            f"✅ Split individual removido de **{product['name']}**.\n{detail}",
            ephemeral=True,
        )

    @app_commands.command(
        name="split-status",
        description="Mostra a divisão efetiva configurada em um produto",
    )
    @app_commands.describe(produto_id="ID local do produto")
    async def split_status(self, i: discord.Interaction, produto_id: int):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        product, _state = resolve_product_for_guild(
            produto_id, i.guild.id, repair=False
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.\n"
                "Use `/loja produtos` para conferir os IDs locais.",
                ephemeral=True,
            )
            return

        try:
            split = get_product_split(product)
        except ValueError as exc:
            await i.response.send_message(
                f"⚠️ Configuração de split inválida: `{exc}`",
                ephemeral=True,
            )
            return

        if not split:
            override = int(_row_value(product, "split_override", 0) or 0) == 1
            reason = (
                "bloqueio individual (override)" if override
                else "nenhuma regra individual ou de grupo"
            )
            await i.response.send_message(
                f"📦 **{product['name']}** (`#{produto_id}`)\n"
                "🤝 Split efetivo: **DESATIVADO**\n"
                f"ℹ️ Motivo: **{reason}**\n"
                "🏦 Destino: **100% para a MisticPay principal do servidor**.",
                ephemeral=True,
            )
            return

        if split.get("source") == "painel":
            source_text = f"Painel `{split.get('group')}`"
        elif split.get("source") == "grupo":
            source_text = f"Grupo legado `{split.get('group')}`"
        else:
            source_text = "Configuração individual do produto"
        await i.response.send_message(
            f"📦 **{product['name']}** (`#{produto_id}`)\n"
            "🤝 Split efetivo: **ATIVADO**\n"
            f"🧩 Origem: **{source_text}**\n"
            f"🏦 Conta principal: **{100 - split['tax']:g}%**\n"
            f"👤 `{split['user']}`: **{split['tax']:g}%**",
            ephemeral=True,
        )

    @app_commands.command(
        name="splits",
        description="Lista splits por painel, grupo legado e produto individual",
    )
    async def splits_list(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        con = db()
        try:
            rows = con.execute(
                """
                SELECT id,local_id,name,split_user,split_tax
                FROM products
                WHERE guild_id=? AND split_enabled=1
                ORDER BY local_id ASC
                LIMIT 60
                """,
                (i.guild.id,),
            ).fetchall()
            groups = con.execute(
                """
                SELECT match_text,split_user,split_tax,panel_id,panel_name
                FROM split_group_rules
                WHERE guild_id=? AND active=1
                ORDER BY id DESC
                LIMIT 60
                """,
                (i.guild.id,),
            ).fetchall()
        finally:
            con.close()

        if not rows and not groups:
            await i.response.send_message(
                "🤝 Nenhum split ativo.",
                ephemeral=True,
            )
            return

        sections = []

        panel_lines = []
        legacy_lines = []
        for row in groups:
            tax = float(row["split_tax"] or 0)
            panel_id = _row_value(row, "panel_id", None)
            if panel_id is not None:
                pname = str(_row_value(row, "panel_name", "") or f"Painel #{panel_id}")
                try:
                    count = len(get_panel_products(i.guild.id, int(panel_id)))
                except Exception:
                    count = 0
                panel_lines.append(
                    f"🖼️ **{pname}** • {count} opção(ões) • "
                    f"{100 - tax:g}% / {tax:g}% `{row['split_user']}`"
                )
            else:
                legacy_lines.append(
                    f"🧩 `{row['match_text']}` • "
                    f"{100 - tax:g}% / {tax:g}% `{row['split_user']}`"
                )

        if panel_lines:
            sections.append("**Splits por painel**\n" + "\n".join(panel_lines))
        if legacy_lines:
            sections.append("**Grupos antigos por nome-base**\n" + "\n".join(legacy_lines))

        if rows:
            lines = []
            for row in rows:
                tax = float(row["split_tax"] or 0)
                lines.append(
                    f"📦 `#{row['local_id']}` • **{row['name']}** • "
                    f"{100 - tax:g}% / {tax:g}% `{row['split_user']}`"
                )
            sections.append("**Overrides individuais**\n" + "\n".join(lines))

        await i.response.send_message(
            embed=discord.Embed(
                title="🤝 Splits configurados",
                description="\n\n".join(sections)[:4000],
                color=0x8B2CF5,
            ),
            ephemeral=True,
        )

    @app_commands.command(
        name="split-grupo",
        description="Ativa split em todas as opções de um painel de vendas",
    )
    @app_commands.describe(
        nome="Nome que aparece no painel. Ex: Estabilizador Emulador",
        email="E-mail MisticPay que recebe a porcentagem",
        porcentagem="Porcentagem enviada à outra conta. Padrão: 50",
        forcar="True = remove overrides individuais das opções deste painel",
    )
    @app_commands.autocomplete(nome=split_panel_autocomplete)
    async def split_group_configure(
        self,
        i: discord.Interaction,
        nome: str,
        email: str,
        porcentagem: float = 50.0,
        forcar: bool = False,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        try:
            split_user = validate_split_email(email)
        except ValueError as exc:
            await i.response.send_message(f"❌ {exc}", ephemeral=True)
            return

        porcentagem = round(float(porcentagem), 2)
        if porcentagem <= 0 or porcentagem >= 100:
            await i.response.send_message(
                "❌ A porcentagem precisa ser maior que 0 e menor que 100.",
                ephemeral=True,
            )
            return

        panel = resolve_split_panel(i.guild.id, nome)
        if not panel:
            suggestions = get_split_panels(i.guild.id, nome, limit=10)
            if not suggestions:
                suggestions = get_split_panels(i.guild.id, limit=10)
            list_text = "\n".join(
                f"• `{panel_display_name(row)}`"
                for row in suggestions
            ) or "Nenhum painel encontrado."
            await i.response.send_message(
                "❌ **Painel não encontrado.**\n\n"
                "Use exatamente o nome que aparece no topo do painel de vendas.\n\n"
                f"**Painéis encontrados:**\n{list_text}",
                ephemeral=True,
            )
            return

        panel_id = int(panel["id"])
        panel_name = panel_display_name(panel)
        matches = get_panel_products(i.guild.id, panel_id)

        if not matches:
            await i.response.send_message(
                f"❌ O painel **{panel_name}** existe, mas não tem produtos/opções vinculados.",
                ephemeral=True,
            )
            return

        con = db()
        try:
            now = now_iso()
            rule_key = f"panel:{panel_id}"
            con.execute(
                """
                INSERT INTO split_group_rules(
                    guild_id,match_text,split_user,split_tax,active,
                    created_at,updated_at,panel_id,panel_name
                ) VALUES(?,?,?,?,1,?,?,?,?)
                ON CONFLICT(guild_id,match_text) DO UPDATE SET
                    split_user=excluded.split_user,
                    split_tax=excluded.split_tax,
                    active=1,
                    updated_at=excluded.updated_at,
                    panel_id=excluded.panel_id,
                    panel_name=excluded.panel_name
                """,
                (
                    i.guild.id,
                    rule_key,
                    split_user,
                    porcentagem,
                    now,
                    now,
                    panel_id,
                    panel_name,
                ),
            )

            if forcar:
                product_ids = [int(row["id"]) for row in matches]
                placeholders = ",".join("?" for _ in product_ids)
                con.execute(
                    f"""
                    UPDATE products
                    SET split_enabled=0,split_user=NULL,split_tax=0,split_override=0
                    WHERE guild_id=? AND id IN ({placeholders})
                    """,
                    tuple([i.guild.id] + product_ids),
                )
            con.commit()
        finally:
            con.close()

        lines = []
        overridden = 0
        for row in matches:
            override = int(_row_value(row, "split_override", 0) or 0) == 1
            enabled = int(_row_value(row, "split_enabled", 0) or 0) == 1
            if (override or enabled) and not forcar:
                overridden += 1
                mark = "⚠️ split individual preservado"
            else:
                mark = "✅ herda o painel"
            lines.append(
                f"`#{row['local_id']}` • **{row['name']}** • {mark}"
            )

        warning = ""
        if overridden:
            warning = (
                f"\n\n⚠️ **{overridden} opção(ões)** já têm regra individual. "
                "Use `forcar:True` se quiser que o painel controle essas opções também."
            )

        await i.response.send_message(
            "✅ **Split do painel configurado.**\n\n"
            f"🖼️ Painel: **{panel_name}**\n"
            f"📦 Opções vinculadas: **{len(matches)}**\n"
            f"🏦 Principal: **{100 - porcentagem:g}%**\n"
            f"🤝 `{split_user}`: **{porcentagem:g}%**\n\n"
            "**Todas as opções deste painel:**\n"
            + "\n".join(lines)[:2600]
            + warning
            + "\n\n💡 Se você adicionar outro produto a esse painel depois, "
              "ele também herda o split automaticamente.",
            ephemeral=True,
        )

    @app_commands.command(
        name="split-grupo-remover",
        description="Remove o split automático de um painel",
    )
    @app_commands.describe(nome="Nome do painel usado em /loja split-grupo")
    @app_commands.autocomplete(nome=split_panel_autocomplete)
    async def split_group_remove(self, i: discord.Interaction, nome: str):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        panel = resolve_split_panel(i.guild.id, nome)
        con = db()
        try:
            removed = 0
            if panel:
                panel_id = int(panel["id"])
                cur = con.execute(
                    """
                    DELETE FROM split_group_rules
                    WHERE guild_id=? AND panel_id=?
                    """,
                    (i.guild.id, panel_id),
                )
                removed = int(getattr(cur, "rowcount", 0) or 0)
                label = panel_display_name(panel)
            else:
                # Compatibilidade para remover uma regra antiga por nome-base.
                try:
                    match_text = normalize_split_group(nome)
                except ValueError:
                    match_text = normalize_panel_label(nome)
                cur = con.execute(
                    """
                    DELETE FROM split_group_rules
                    WHERE guild_id=? AND panel_id IS NULL AND match_text=?
                    """,
                    (i.guild.id, match_text),
                )
                removed = int(getattr(cur, "rowcount", 0) or 0)
                label = nome
            con.commit()
        finally:
            con.close()

        await i.response.send_message(
            (
                f"✅ Split automático de **{label}** removido. "
                "Splits individuais antigos foram preservados."
                if removed
                else f"⚠️ Não existe split automático para **{label}**."
            ),
            ephemeral=True,
        )

    @app_commands.command(
        name="split-diagnostico",
        description="Mostra o split efetivo e os últimos pedidos do produto",
    )
    @app_commands.describe(produto_id="ID local do produto neste servidor")
    async def split_diagnostic(self, i: discord.Interaction, produto_id: int):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        product, _state = resolve_product_for_guild(produto_id, i.guild.id, repair=False)
        if not product:
            await i.response.send_message(f"❌ Produto `#{produto_id}` não encontrado.", ephemeral=True)
            return

        try:
            split = get_product_split(product)
            err = None
        except Exception as exc:
            split = None
            err = str(exc)

        con = db()
        try:
            rows = con.execute(
                """
                SELECT id,status,amount,split_user,split_tax,split_amount,
                       split_source,split_group,created_at
                FROM orders
                WHERE guild_id=? AND product_id=?
                ORDER BY id DESC
                LIMIT 5
                """,
                (i.guild.id, int(product["id"])),
            ).fetchall()
        finally:
            con.close()

        if err:
            effective = f"❌ Configuração inválida: `{err}`"
        elif split:
            if split.get("source") == "painel":
                src = f"painel `{split.get('group')}`"
            elif split.get("source") == "grupo":
                src = f"grupo legado `{split.get('group')}`"
            else:
                src = "produto individual"
            effective = (
                f"✅ **ATIVO** por {src}\n"
                f"Principal: **{100 - split['tax']:g}%** • `{split['user']}`: **{split['tax']:g}%**"
            )
        else:
            effective = "❌ **DESATIVADO** → 100% para a conta principal"

        history = []
        for row in rows:
            tax = float(_row_value(row, "split_tax", 0) or 0)
            src = _row_value(row, "split_source", None) or ("produto" if tax else "nenhum")
            grp = _row_value(row, "split_group", None)
            suffix = f" • grupo={grp}" if grp else ""
            history.append(
                f"`#{row['id']}` {row['status']} • {money(row['amount'])} • split={tax:g}% • fonte={src}{suffix}"
            )

        await i.response.send_message(
            embed=discord.Embed(
                title="🧪 Diagnóstico de Split",
                description=(
                    f"📦 **{product['name']}** (`#{produto_id}`)\n\n"
                    f"**Próximo PIX:**\n{effective}\n\n"
                    "**Últimos pedidos:**\n"
                    + ("\n".join(history) if history else "Nenhum pedido encontrado.")
                )[:4000],
                color=0x8B2CF5,
            ),
            ephemeral=True,
        )

    @app_commands.command(
        name="cupom-criar",
        description="Cria cupom para um produto específico",
    )
    @app_commands.describe(
        nome="Código do cupom. Ex: LINK",
        desconto="Desconto em %. Ex: 5",
        produto_id="ID LOCAL do produto neste servidor",
        quantidade="Quantidade máxima de utilizações. Ex: 10",
    )
    async def coupon_create(
        self,
        i: discord.Interaction,
        nome: str,
        desconto: float,
        produto_id: int,
        quantidade: int = 10,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        coupon_code = normalize_coupon_code(nome)
        if not coupon_code:
            await i.response.send_message(
                "❌ Nome de cupom inválido.",
                ephemeral=True,
            )
            return

        desconto = round(float(desconto), 2)
        if desconto <= 0 or desconto >= 100:
            await i.response.send_message(
                "❌ O desconto precisa ser maior que 0% e menor que 100%.",
                ephemeral=True,
            )
            return

        if quantidade <= 0 or quantidade > 100000:
            await i.response.send_message(
                "❌ A quantidade precisa ser entre 1 e 100000.",
                ephemeral=True,
            )
            return

        product, _state = resolve_product_for_guild(
            produto_id,
            i.guild.id,
            repair=False,
        )
        if not product:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.\n"
                "Use `/loja produtos` para conferir os IDs.",
                ephemeral=True,
            )
            return

        con = db()
        exists = con.execute(
            "SELECT id FROM coupons WHERE guild_id=? AND code=?",
            (i.guild.id, coupon_code),
        ).fetchone()
        if exists:
            con.close()
            await i.response.send_message(
                f"⚠️ O cupom `{coupon_code}` já existe. "
                "Use `/loja cupom-editar` ou remova o antigo.",
                ephemeral=True,
            )
            return

        con.execute(
            """
            INSERT INTO coupons(
                guild_id,code,discount_percent,product_id,
                max_uses,used_count,active,created_at,updated_at
            ) VALUES(?,?,?,?,?,0,1,?,?)
            """,
            (
                i.guild.id,
                coupon_code,
                desconto,
                int(product["id"]),
                quantidade,
                now_iso(),
                now_iso(),
            ),
        )
        con.commit()
        con.close()

        await i.response.send_message(
            "✅ **Cupom criado!**\n\n"
            f"🎟️ Código: `{coupon_code}`\n"
            f"📦 Produto: **{product['name']}** (`#{produto_id}`)\n"
            f"💸 Desconto: **{desconto:g}%**\n"
            f"🔢 Utilizações: **{quantidade}**\n"
            "🟢 Status: **ATIVO**",
            ephemeral=True,
        )

    @app_commands.command(
        name="cupom-editar",
        description="Edita desconto, produto ou quantidade de um cupom",
    )
    @app_commands.describe(
        nome="Código do cupom",
        desconto="Novo desconto em %",
        produto_id="Novo ID LOCAL do produto",
        quantidade="Nova quantidade máxima de utilizações",
        zerar_usos="True para zerar o contador de usos",
    )
    async def coupon_edit(
        self,
        i: discord.Interaction,
        nome: str,
        desconto: Optional[float] = None,
        produto_id: Optional[int] = None,
        quantidade: Optional[int] = None,
        zerar_usos: bool = False,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        coupon_code = normalize_coupon_code(nome)
        row = get_coupon_any_state(i.guild.id, coupon_code)
        if not row:
            await i.response.send_message(
                f"❌ Cupom `{coupon_code}` não encontrado.",
                ephemeral=True,
            )
            return

        new_discount = (
            round(float(desconto), 2)
            if desconto is not None
            else float(row["discount_percent"])
        )
        if new_discount <= 0 or new_discount >= 100:
            await i.response.send_message(
                "❌ O desconto precisa ser maior que 0% e menor que 100%.",
                ephemeral=True,
            )
            return

        new_product_id = row["product_id"]
        product_name = "Cupom geral antigo"
        local_product_id = None

        if produto_id is not None:
            product, _state = resolve_product_for_guild(
                produto_id,
                i.guild.id,
                repair=False,
            )
            if not product:
                await i.response.send_message(
                    f"❌ Produto `#{produto_id}` não encontrado neste servidor.",
                    ephemeral=True,
                )
                return
            new_product_id = int(product["id"])
            product_name = product["name"]
            local_product_id = produto_id
        elif new_product_id is not None:
            con = db()
            product = con.execute(
                "SELECT * FROM products WHERE id=? AND guild_id=?",
                (new_product_id, i.guild.id),
            ).fetchone()
            con.close()
            if product:
                product_name = product["name"]
                local_product_id = product["local_id"]

        new_max_uses = int(quantidade) if quantidade is not None else row["max_uses"]
        if new_max_uses is not None and (
            int(new_max_uses) <= 0 or int(new_max_uses) > 100000
        ):
            await i.response.send_message(
                "❌ A quantidade precisa ser entre 1 e 100000.",
                ephemeral=True,
            )
            return

        used_count = 0 if zerar_usos else int(row["used_count"] or 0)
        if new_max_uses is not None and used_count > int(new_max_uses):
            used_count = int(new_max_uses)

        con = db()
        con.execute(
            """
            UPDATE coupons
            SET discount_percent=?,
                product_id=?,
                max_uses=?,
                used_count=?,
                updated_at=?
            WHERE guild_id=? AND code=?
            """,
            (
                new_discount,
                new_product_id,
                new_max_uses,
                used_count,
                now_iso(),
                i.guild.id,
                coupon_code,
            ),
        )
        con.commit()
        con.close()

        await i.response.send_message(
            "✅ **Cupom atualizado!**\n\n"
            f"🎟️ `{coupon_code}`\n"
            f"📦 Produto: **{product_name}**"
            + (f" (`#{local_product_id}`)\n" if local_product_id is not None else "\n")
            + f"💸 Desconto: **{new_discount:g}%**\n"
            + f"🔢 Limite: **{new_max_uses if new_max_uses is not None else '∞'}**\n"
            + f"✅ Usados: **{used_count}**",
            ephemeral=True,
        )

    @app_commands.command(
        name="cupom-desativar",
        description="Desativa um cupom sem excluir",
    )
    async def coupon_disable(self, i: discord.Interaction, nome: str):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        coupon_code = normalize_coupon_code(nome)
        row = get_coupon_any_state(i.guild.id, coupon_code)
        if not row:
            await i.response.send_message("❌ Cupom não encontrado.", ephemeral=True)
            return

        con = db()
        con.execute(
            "UPDATE coupons SET active=0,updated_at=? WHERE guild_id=? AND code=?",
            (now_iso(), i.guild.id, coupon_code),
        )
        con.execute(
            "DELETE FROM cart_coupons WHERE guild_id=? AND coupon_code=?",
            (i.guild.id, coupon_code),
        )
        con.commit()
        con.close()
        await i.response.send_message(
            f"⏸️ Cupom `{coupon_code}` desativado.",
            ephemeral=True,
        )

    @app_commands.command(
        name="cupom-ativar",
        description="Ativa novamente um cupom",
    )
    async def coupon_enable(self, i: discord.Interaction, nome: str):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        coupon_code = normalize_coupon_code(nome)
        row = get_coupon_any_state(i.guild.id, coupon_code)
        if not row:
            await i.response.send_message("❌ Cupom não encontrado.", ephemeral=True)
            return

        max_uses = row["max_uses"]
        used = int(row["used_count"] or 0)
        if coupon_is_expired(row):
            await i.response.send_message(
                "❌ Esse cupom já expirou. Execute novamente "
                "`/cupom todos-produtos` para definir um novo prazo.",
                ephemeral=True,
            )
            return
        if max_uses is not None and used >= int(max_uses):
            await i.response.send_message(
                "❌ Esse cupom já esgotou as utilizações. "
                "Use `/loja cupom-editar` aumentando a quantidade ou `zerar_usos:True`.",
                ephemeral=True,
            )
            return

        con = db()
        con.execute(
            "UPDATE coupons SET active=1,updated_at=? WHERE guild_id=? AND code=?",
            (now_iso(), i.guild.id, coupon_code),
        )
        con.commit()
        con.close()
        await i.response.send_message(
            f"▶️ Cupom `{coupon_code}` ativado.",
            ephemeral=True,
        )

    @app_commands.command(
        name="cupom-remover",
        description="Exclui definitivamente um cupom",
    )
    async def coupon_remove(self, i: discord.Interaction, nome: str):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        coupon_code = normalize_coupon_code(nome)
        row = get_coupon_any_state(i.guild.id, coupon_code)
        if not row:
            await i.response.send_message(
                f"❌ Cupom `{coupon_code}` não encontrado.",
                ephemeral=True,
            )
            return

        con = db()
        con.execute(
            "DELETE FROM coupons WHERE guild_id=? AND code=?",
            (i.guild.id, coupon_code),
        )
        con.execute(
            "DELETE FROM cart_coupons WHERE guild_id=? AND coupon_code=?",
            (i.guild.id, coupon_code),
        )
        con.commit()
        con.close()

        await i.response.send_message(
            f"🗑️ Cupom `{coupon_code}` excluído definitivamente.",
            ephemeral=True,
        )

    @app_commands.command(
        name="cupons",
        description="Lista cupons, produtos e quantidades restantes",
    )
    async def coupons_list(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        con = db()
        rows = con.execute(
            """
            SELECT
                c.code,c.discount_percent,c.active,
                c.max_uses,c.used_count,c.product_id,c.expires_at,
                p.name AS product_name,p.local_id
            FROM coupons c
            LEFT JOIN products p
              ON p.id=c.product_id AND p.guild_id=c.guild_id
            WHERE c.guild_id=?
            ORDER BY c.active DESC,c.code ASC
            LIMIT 80
            """,
            (i.guild.id,),
        ).fetchall()
        con.close()

        if not rows:
            await i.response.send_message(
                "🎟️ Nenhum cupom configurado ainda.",
                ephemeral=True,
            )
            return

        lines = []
        for r in rows:
            max_uses = r["max_uses"]
            used = int(r["used_count"] or 0)
            remaining = "∞" if max_uses is None else str(max(0, int(max_uses) - used))
            expired = coupon_is_expired(r)
            status = "⌛" if expired else ("🟢" if int(r["active"] or 0) == 1 else "🔴")
            product_txt = (
                f"{r['product_name']} #{r['local_id']}"
                if r["product_name"]
                else "todos os produtos"
            )
            expires = coupon_expiration(r)
            expiry_txt = (
                f" • ⏳ <t:{int(expires.timestamp())}:R>" if expires else ""
            )
            lines.append(
                f"{status} `{r['code']}` • **{float(r['discount_percent']):g}%** "
                f"• 📦 {product_txt} • 🎟️ restantes: **{remaining}**{expiry_txt}"
            )

        embed = discord.Embed(
            title="🎟️ Cupons da Entregas Automáticas",
            description="\n".join(lines)[:4000],
            color=0x8B2CF5,
        )
        await i.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(
        name="dashboard", description="Dashboard de faturamento e vendas"
    )
    async def dashboard(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        con = db()
        gid = i.guild.id
        total = con.execute(
            "SELECT COALESCE(SUM(amount),0) v,COUNT(*) c FROM orders WHERE guild_id=? AND status='aprovado' AND is_test=0",
            (gid,),
        ).fetchone()
        hoje = con.execute(
            "SELECT COALESCE(SUM(amount),0) v,COUNT(*) c FROM orders WHERE guild_id=? AND status='aprovado' AND is_test=0 AND date(COALESCE(paid_at,created_at))=date('now')",
            (gid,),
        ).fetchone()
        mes = con.execute(
            "SELECT COALESCE(SUM(amount),0) v,COUNT(*) c FROM orders WHERE guild_id=? AND status='aprovado' AND is_test=0 AND strftime('%Y-%m',COALESCE(paid_at,created_at))=strftime('%Y-%m','now')",
            (gid,),
        ).fetchone()
        pend = con.execute(
            "SELECT COUNT(*) c FROM orders WHERE guild_id=? AND status='pendente'",
            (gid,),
        ).fetchone()["c"]
        top = con.execute(
            "SELECT product_name,COUNT(*) q,SUM(amount) v FROM orders WHERE guild_id=? AND status='aprovado' AND is_test=0 GROUP BY product_name ORDER BY q DESC LIMIT 5",
            (gid,),
        ).fetchall()
        con.close()
        e = discord.Embed(title="📊 ENTREGAS AUTOMÁTICAS | Dashboard", color=0x8B2CF5)
        e.add_field(name="💰 Total", value=money(total["v"]))
        e.add_field(name="📅 Hoje", value=f"{money(hoje['v'])} • {hoje['c']}")
        e.add_field(name="🗓️ Mês", value=f"{money(mes['v'])} • {mes['c']}")
        e.add_field(name="✅ Vendas reais", value=str(total["c"]))
        e.add_field(name="🟡 Pendentes", value=str(pend))
        e.add_field(
            name="🏆 Mais vendidos",
            value="\n".join(f"{r['product_name']}: {r['q']}" for r in top) or "Nenhum",
            inline=False,
        )
        try:
            bal = await api("GET", "/users/balance", guild_id=i.guild.id)
            e.add_field(
                name="🏦 Saldo MisticPay",
                value=money((bal.get("data") or {}).get("balance", 0)),
            )
        except:
            e.add_field(name="🏦 Saldo MisticPay", value="Indisponível")
        await i.response.send_message(embed=e, ephemeral=True)

    @app_commands.command(
        name="produtos", description="Lista produtos por página, começando do ID #1"
    )
    @app_commands.describe(
        pagina="Página da lista. Ex: 1, 2, 3..."
    )
    async def products(self, i: discord.Interaction, pagina: int = 1):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        pagina = max(1, int(pagina or 1))
        per_page = 25
        offset = (pagina - 1) * per_page

        con = db()
        try:
            total_row = con.execute(
                "SELECT COUNT(*) AS c FROM products WHERE guild_id=?",
                (i.guild.id,),
            ).fetchone()
            total = int(total_row["c"] or 0)

            rows = con.execute(
                """
                SELECT
                    id,local_id,name,price,stock,active,
                    license_enabled,purchase_role_id
                FROM products
                WHERE guild_id=?
                ORDER BY local_id ASC
                LIMIT ? OFFSET ?
                """,
                (i.guild.id, per_page, offset),
            ).fetchall()
        finally:
            con.close()

        pages = max(1, math.ceil(total / per_page)) if total else 1
        if pagina > pages and total:
            await i.response.send_message(
                f"❌ Essa página não existe. Última página: **{pages}**.",
                ephemeral=True,
            )
            return

        body = (
            "\n".join(
                (
                    f"`#{r['local_id']}` • **{r['name']}** • {money(r['price'])} • "
                    f"{'ativo' if r['active'] else 'inativo'}"
                    + (" • 🔑 Key" if int(r["license_enabled"] or 0) == 1 else "")
                    + (" • 🎭 Cargo" if r["purchase_role_id"] else "")
                )
                for r in rows
            )
            or "Nenhum produto."
        )

        await i.response.send_message(
            embed=discord.Embed(
                title=f"📦 Produtos • Página {pagina}/{pages}",
                description=(body + f"\n\n**Total:** {total} produto(s)")[:4000],
                color=0x8B2CF5,
            ),
            ephemeral=True,
        )

    @app_commands.command(
        name="excluir-produto", description="Exclui ou desativa um produto"
    )
    async def delete(
        self, i: discord.Interaction, produto_id: int, definitivo: bool = False
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        p, _state = resolve_product_for_guild(produto_id, i.guild.id, repair=False)
        if not p:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.",
                ephemeral=True,
            )
            return

        global_product_id = int(p["id"])
        con = db()
        used = con.execute(
            "SELECT COUNT(*) c FROM orders WHERE product_id=?",
            (global_product_id,),
        ).fetchone()["c"]
        if definitivo and used == 0:
            con.execute(
                "DELETE FROM panel_products WHERE product_id=?", (global_product_id,)
            )
            con.execute("DELETE FROM products WHERE id=?", (global_product_id,))
            msg = "Excluído definitivamente."
        else:
            con.execute("UPDATE products SET active=0 WHERE id=?", (global_product_id,))
            msg = "Desativado."
        con.commit()
        con.close()
        await i.response.send_message("✅ " + msg, ephemeral=True)

    @app_commands.command(
        name="teste-gratis", description="Simula compra aprovada sem cobrar"
    )
    async def test(
        self,
        i: discord.Interaction,
        produto_id: int,
        cliente: Optional[discord.Member] = None,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        cliente = cliente or i.user
        p, _state = resolve_product_for_guild(produto_id, i.guild.id, repair=False)
        if not p:
            await i.response.send_message(
                f"❌ Produto `#{produto_id}` não encontrado neste servidor.",
                ephemeral=True,
            )
            return
        global_product_id = int(p["id"])
        await i.response.defer(ephemeral=True, thinking=True)
        con = db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO orders(guild_id,user_id,product_id,product_name,amount,status,code,is_test,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                i.guild.id,
                cliente.id,
                global_product_id,
                p["name"],
                p["price"],
                "pendente",
                "TESTE-" + code(),
                1,
                now_iso(),
            ),
        )
        oid = cur.lastrowid
        con.commit()
        con.close()
        ok, msg = await verify(oid, True)
        await i.followup.send(
            msg
            + f"\n🧪 Teste #{oid}: sem cobrança, sem faturamento e sem reduzir estoque.",
            ephemeral=True,
        )

    @app_commands.command(
        name="split-expandir",
        description="Mostra todas as opções de um painel e o split efetivo",
    )
    @app_commands.describe(
        painel="Nome que aparece no painel de vendas"
    )
    @app_commands.autocomplete(painel=split_panel_autocomplete)
    async def split_expand(self, i: discord.Interaction, painel: str):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        panel = resolve_split_panel(i.guild.id, painel)
        if not panel:
            choices = get_split_panels(i.guild.id, painel, limit=20)
            if not choices:
                choices = get_split_panels(i.guild.id, limit=20)
            lines = "\n".join(
                f"• `{panel_display_name(row)}`"
                for row in choices
            ) or "Nenhum painel encontrado."
            await i.response.send_message(
                "❌ Painel não encontrado.\n\n"
                f"**Painéis disponíveis:**\n{lines}",
                ephemeral=True,
            )
            return

        panel_id = int(panel["id"])
        panel_name = panel_display_name(panel)
        products = get_panel_products(i.guild.id, panel_id)

        if not products:
            await i.response.send_message(
                f"🖼️ **{panel_name}** não possui produtos vinculados.",
                ephemeral=True,
            )
            return

        lines = []
        for product in products:
            try:
                split = get_product_split(product)
            except Exception as exc:
                lines.append(
                    f"`#{product['local_id']}` • **{product['name']}** • ❌ `{str(exc)[:80]}`"
                )
                continue

            if not split:
                status = "100% principal"
            elif split.get("source") == "painel":
                status = f"✅ {split['tax']:g}% split pelo painel"
            elif split.get("source") == "produto":
                status = f"⚠️ {split['tax']:g}% split individual"
            else:
                status = f"🧩 {split['tax']:g}% grupo legado"

            lines.append(
                f"`#{product['local_id']}` • **{product['name']}** • {status}"
            )

        description = (
            f"🖼️ **{panel_name}**\n"
            f"🆔 Painel interno: `{panel_id}`\n"
            f"📦 Total de opções: **{len(products)}**\n\n"
            + "\n".join(lines)
        )

        await i.response.send_message(
            embed=discord.Embed(
                title="🔎 Split • Opções do painel",
                description=description[:4000],
                color=0x8B2CF5,
            ),
            ephemeral=True,
        )


def get_streamer_dashboard(guild_id, discord_user_id):
    affiliate = get_affiliate_by_member(guild_id, discord_user_id)
    if not affiliate:
        return None, None
    con = db()
    try:
        stats = con.execute(
            """
            SELECT
                COUNT(*) AS sales_count,
                COUNT(DISTINCT user_id) AS unique_buyers,
                COALESCE(SUM(amount),0) AS gross_total,
                COALESCE(SUM(affiliate_amount),0) AS commission_total,
                MAX(paid_at) AS last_sale
            FROM orders
            WHERE guild_id=?
              AND affiliate_user_id=?
              AND status='aprovado'
              AND COALESCE(is_test,0)=0
            """,
            (int(guild_id), int(discord_user_id)),
        ).fetchone()
    finally:
        con.close()
    return affiliate, stats


def build_streamer_dashboard_embed(guild, member):
    affiliate, stats = get_streamer_dashboard(guild.id, member.id)
    if not affiliate:
        return None
    sales_count = int(_row_value(stats, "sales_count", 0) or 0)
    unique_buyers = int(_row_value(stats, "unique_buyers", 0) or 0)
    gross_total = float(_row_value(stats, "gross_total", 0) or 0)
    commission_total = float(_row_value(stats, "commission_total", 0) or 0)
    last_sale = _parse_db_datetime(_row_value(stats, "last_sale"))
    last_sale_text = (
        f"<t:{int(last_sale.timestamp())}:R>" if last_sale else "Nenhuma ainda"
    )
    active = int(affiliate["active"] or 0) == 1
    embed = discord.Embed(
        title=f"📊 Painel Streamer • {affiliate['display_name']}",
        description=(
            f"📣 Resultados públicos das compras atribuídas a {member.mention}.\n"
            "Os números consideram somente pagamentos reais confirmados."
        ),
        color=0xE31B2B,
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="🛒 Compras", value=f"**{sales_count}**", inline=True)
    embed.add_field(name="👥 Clientes únicos", value=f"**{unique_buyers}**", inline=True)
    embed.add_field(name="💵 Valor gerado", value=f"**{money(gross_total)}**", inline=True)
    embed.add_field(
        name="💸 Comissão do streamer",
        value=f"**{money(commission_total)}**",
        inline=True,
    )
    embed.add_field(
        name="📈 Comissão atual",
        value=f"**{float(affiliate['commission_percent']):g}%**",
        inline=True,
    )
    embed.add_field(name="🕐 Última compra", value=last_sale_text, inline=True)
    embed.add_field(
        name="🔎 Status",
        value="🟢 Afiliado ativo" if active else "🔴 Afiliado desativado",
        inline=False,
    )
    try:
        embed.set_thumbnail(url=member.display_avatar.url)
    except Exception:
        pass
    embed.set_footer(text="LOCK SENSI • Painel de Afiliados • Atualização ao vivo")
    return embed


class StreamerDashboardView(discord.ui.View):
    def __init__(self, guild_id, streamer_user_id):
        super().__init__(timeout=3600)
        self.guild_id = int(guild_id)
        self.streamer_user_id = int(streamer_user_id)

    @discord.ui.button(
        label="Atualizar painel",
        emoji="🔄",
        style=discord.ButtonStyle.secondary,
    )
    async def refresh(self, i: discord.Interaction, b):
        guild = i.client.get_guild(self.guild_id) or i.guild
        member = guild.get_member(self.streamer_user_id) if guild else None
        if guild and not member:
            try:
                member = await guild.fetch_member(self.streamer_user_id)
            except Exception:
                member = None
        if not guild or not member:
            await i.response.send_message(
                "❌ Não consegui localizar esse streamer.", ephemeral=True
            )
            return
        embed = build_streamer_dashboard_embed(guild, member)
        if not embed:
            await i.response.send_message(
                "❌ Esse usuário não está cadastrado como afiliado.", ephemeral=True
            )
            return
        await i.response.edit_message(
            embed=embed,
            view=StreamerDashboardView(self.guild_id, self.streamer_user_id),
        )


class AffiliateCommands(app_commands.Group):
    def __init__(self):
        super().__init__(
            name="afiliado",
            description="Streamers, indicações e comissões Lock Sensi",
        )

    @app_commands.command(
        name="cadastrar",
        description="Cadastra ou atualiza um streamer afiliado",
    )
    @app_commands.describe(
        usuario="Streamer do Discord",
        email="E-mail da conta MisticPay do streamer",
        porcentagem="Comissão em cada venda indicada. Ex: 10",
        nome="Nome exibido no painel (opcional)",
    )
    async def register(
        self,
        i: discord.Interaction,
        usuario: discord.Member,
        email: str,
        porcentagem: float,
        nome: Optional[str] = None,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        try:
            email = validate_split_email(email)
            porcentagem = _validate_percent(porcentagem, "Comissão")
        except ValueError as exc:
            await i.response.send_message(f"❌ {exc}", ephemeral=True)
            return
        subowner = get_subowner(i.guild.id)
        if subowner and porcentagem + float(subowner["percent"] or 0) >= 100:
            await i.response.send_message(
                "❌ Comissão do afiliado + porcentagem do subdono precisa "
                "deixar ao menos 1% para a conta principal.",
                ephemeral=True,
            )
            return
        display_name = re.sub(r"\s+", " ", str(nome or usuario.display_name)).strip()
        if not display_name:
            display_name = usuario.display_name
        con = db()
        try:
            con.execute(
                """
                INSERT INTO affiliates(
                    guild_id,discord_user_id,display_name,mistic_email,
                    commission_percent,active,created_by,created_at,updated_at
                ) VALUES(?,?,?,?,?,1,?,?,?)
                ON CONFLICT(guild_id,discord_user_id) DO UPDATE SET
                    display_name=excluded.display_name,
                    mistic_email=excluded.mistic_email,
                    commission_percent=excluded.commission_percent,
                    active=1,
                    updated_at=excluded.updated_at
                """,
                (
                    i.guild.id,
                    usuario.id,
                    display_name[:100],
                    email,
                    porcentagem,
                    i.user.id,
                    now_iso(),
                    now_iso(),
                ),
            )
            con.commit()
        finally:
            con.close()
        await i.response.send_message(
            "✅ **Afiliado cadastrado.**\n"
            f"📣 Streamer: {usuario.mention}\n"
            f"🏷️ Nome no painel: **{display_name[:100]}**\n"
            f"💸 Comissão: **{porcentagem:g}%**\n"
            f"🏦 MisticPay: `{mask_split_email(email)}`",
            ephemeral=True,
        )

    @app_commands.command(name="remover", description="Desativa um streamer afiliado")
    async def remove(self, i: discord.Interaction, usuario: discord.Member):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        con = db()
        try:
            cur = con.execute(
                """
                UPDATE affiliates SET active=0,updated_at=?
                WHERE guild_id=? AND discord_user_id=? AND active=1
                """,
                (now_iso(), i.guild.id, usuario.id),
            )
            removed = int(getattr(cur, "rowcount", 0) or 0)
            con.execute(
                """
                DELETE FROM cart_affiliates
                WHERE affiliate_id IN (
                    SELECT id FROM affiliates
                    WHERE guild_id=? AND discord_user_id=?
                )
                """,
                (i.guild.id, usuario.id),
            )
            con.commit()
        finally:
            con.close()
        await i.response.send_message(
            "✅ Afiliado removido do painel."
            if removed
            else "⚠️ Esse usuário não era um afiliado ativo.",
            ephemeral=True,
        )

    @app_commands.command(name="listar", description="Mostra os afiliados cadastrados")
    async def list_affiliates(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        rows = get_affiliates(i.guild.id)
        lines = [
            f"📣 <@{row['discord_user_id']}> • **{row['display_name']}** • "
            f"**{float(row['commission_percent']):g}%** • "
            f"`{mask_split_email(row['mistic_email'])}`"
            for row in rows
        ]
        subowner = get_subowner(i.guild.id)
        sub_text = (
            f"Ativo • **{float(subowner['percent']):g}%** • "
            f"`{mask_split_email(subowner['mistic_email'])}`"
            if subowner
            else "Desativado"
        )
        await i.response.send_message(
            embed=discord.Embed(
                title="🤝 Afiliados cadastrados",
                description=(
                    ("\n".join(lines) if lines else "Nenhum afiliado cadastrado.")
                    + f"\n\n**Terceiro participante (subdono):** {sub_text}"
                )[:4000],
                color=0xE31B2B,
            ),
            ephemeral=True,
        )

    @app_commands.command(
        name="subdono-configurar",
        description="Ativa o terceiro participante nas vendas com afiliado",
    )
    @app_commands.describe(
        email="E-mail MisticPay do subdono",
        porcentagem="Parte do valor bruto enviada após confirmação",
    )
    async def configure_subowner(
        self, i: discord.Interaction, email: str, porcentagem: float
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        try:
            email = validate_split_email(email)
            porcentagem = _validate_percent(porcentagem, "Porcentagem do subdono")
        except ValueError as exc:
            await i.response.send_message(f"❌ {exc}", ephemeral=True)
            return
        affiliates = get_affiliates(i.guild.id)
        invalid = [
            row for row in affiliates
            if float(row["commission_percent"] or 0) + porcentagem >= 100
        ]
        if invalid:
            await i.response.send_message(
                "❌ Essa porcentagem não deixa 1% para a conta principal em "
                f"**{len(invalid)} afiliado(s)**. Reduza o valor.",
                ephemeral=True,
            )
            return
        if not mistic_supports_internal_payout(i.guild.id):
            await i.response.send_message(
                "❌ Para três participantes, conecte uma Chave de Acesso "
                "MisticPay `pk_`/`sk_` com permissão **cashout**. "
                "O split antigo de duas contas continua funcionando com `ci_`/`cs_`.",
                ephemeral=True,
            )
            return
        con = db()
        try:
            con.execute(
                """
                INSERT INTO affiliate_subowners(guild_id,mistic_email,percent,active,updated_at)
                VALUES(?,?,?,1,?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    mistic_email=excluded.mistic_email,
                    percent=excluded.percent,
                    active=1,
                    updated_at=excluded.updated_at
                """,
                (i.guild.id, email, porcentagem, now_iso()),
            )
            con.commit()
        finally:
            con.close()
        await i.response.send_message(
            "✅ **Modo de três participantes ativado nas vendas com afiliado.**\n"
            f"👑 Subdono: `{mask_split_email(email)}` • **{porcentagem:g}%**\n"
            "📣 A porcentagem do streamer depende do afiliado escolhido.\n"
            "🏦 A conta principal recebe o restante.",
            ephemeral=True,
        )

    @app_commands.command(
        name="subdono-remover",
        description="Volta as vendas de afiliado para o split de duas contas",
    )
    async def remove_subowner(self, i: discord.Interaction):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        con = db()
        try:
            cur = con.execute(
                "UPDATE affiliate_subowners SET active=0,updated_at=? WHERE guild_id=? AND active=1",
                (now_iso(), i.guild.id),
            )
            changed = int(getattr(cur, "rowcount", 0) or 0)
            con.commit()
        finally:
            con.close()
        await i.response.send_message(
            "✅ Subdono desativado. O split de duas contas foi mantido."
            if changed
            else "⚠️ O subdono já estava desativado.",
            ephemeral=True,
        )

    @app_commands.command(
        name="vendas",
        description="Mostra vendas atribuídas a um streamer",
    )
    async def sales(
        self, i: discord.Interaction, usuario: Optional[discord.Member] = None
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return
        con = db()
        try:
            params = [i.guild.id]
            member_filter = ""
            if usuario:
                member_filter = "AND affiliate_user_id=?"
                params.append(usuario.id)
            rows = con.execute(
                f"""
                SELECT affiliate_user_id,affiliate_name,
                       COUNT(*) AS sales_count,
                       COALESCE(SUM(amount),0) AS gross_total,
                       COALESCE(SUM(affiliate_amount),0) AS commission_total
                FROM orders
                WHERE guild_id=? AND status='aprovado' AND COALESCE(is_test,0)=0
                  AND affiliate_id IS NOT NULL {member_filter}
                GROUP BY affiliate_user_id,affiliate_name
                ORDER BY commission_total DESC
                LIMIT 50
                """,
                tuple(params),
            ).fetchall()
        finally:
            con.close()
        lines = [
            f"<@{row['affiliate_user_id']}> • **{row['sales_count']} venda(s)** • "
            f"bruto {money(row['gross_total'])} • comissão {money(row['commission_total'])}"
            for row in rows
        ]
        await i.response.send_message(
            embed=discord.Embed(
                title="📊 Vendas por afiliado",
                description=("\n".join(lines) or "Nenhuma venda afiliada aprovada.")[:4000],
                color=0xE31B2B,
            ),
            ephemeral=True,
        )

    @app_commands.command(
        name="painel-streamer",
        description="Publica seu dashboard de vendas e comissão no canal",
    )
    async def streamer_panel(self, i: discord.Interaction):
        if not i.guild:
            await i.response.send_message(
                "❌ Use este comando dentro do servidor.", ephemeral=True
            )
            return
        embed = build_streamer_dashboard_embed(i.guild, i.user)
        if not embed:
            await i.response.send_message(
                "❌ Você ainda não está cadastrado como streamer afiliado. "
                "Peça para um administrador usar `/afiliado cadastrar`.",
                ephemeral=True,
            )
            return
        # Resposta normal: o painel fica no chat e todos conseguem visualizar.
        await i.response.send_message(
            embed=embed,
            view=StreamerDashboardView(i.guild.id, i.user.id),
        )


class CouponCommands(app_commands.Group):
    def __init__(self):
        super().__init__(name="cupom", description="Cupons gerais da loja")

    @app_commands.command(
        name="todos-produtos",
        description="Cria um cupom temporário válido para todos os produtos",
    )
    @app_commands.describe(
        nome="Código que o cliente digitará. Ex: LOCKSENSI",
        desconto="Porcentagem de desconto. Ex: 20",
        duracao="Por quanto tempo o cupom ficará ativo",
        unidade="Escolha horas ou dias",
        limite_usos="0 para ilimitado ou a quantidade máxima de usos",
    )
    @app_commands.choices(
        unidade=[
            app_commands.Choice(name="Horas", value="horas"),
            app_commands.Choice(name="Dias", value="dias"),
        ]
    )
    async def all_products(
        self,
        i: discord.Interaction,
        nome: str,
        desconto: float,
        duracao: int,
        unidade: app_commands.Choice[str],
        limite_usos: int = 0,
    ):
        if ADMIN_CHECK and not await ADMIN_CHECK(i):
            return

        coupon_code = normalize_coupon_code(nome)
        if not coupon_code:
            await i.response.send_message("❌ Código de cupom inválido.", ephemeral=True)
            return

        discount = round(float(desconto), 2)
        if discount <= 0 or discount >= 100:
            await i.response.send_message(
                "❌ O desconto precisa ser maior que 0% e menor que 100%.",
                ephemeral=True,
            )
            return

        if duracao <= 0:
            await i.response.send_message(
                "❌ A duração precisa ser maior que zero.", ephemeral=True
            )
            return

        hours = duracao if unidade.value == "horas" else duracao * 24
        if hours > 24 * 365:
            await i.response.send_message(
                "❌ A duração máxima é de 365 dias.", ephemeral=True
            )
            return

        if limite_usos < 0 or limite_usos > 100000:
            await i.response.send_message(
                "❌ O limite deve ser 0 (ilimitado) ou entre 1 e 100000.",
                ephemeral=True,
            )
            return

        expires = datetime.now(timezone.utc) + timedelta(hours=hours)
        expires_db = expires.strftime("%Y-%m-%d %H:%M:%S")
        max_uses = None if limite_usos == 0 else limite_usos

        con = db()
        try:
            con.execute(
                """
                INSERT INTO coupons(
                    guild_id,code,discount_percent,product_id,
                    max_uses,used_count,active,expires_at,created_at,updated_at
                ) VALUES(?,?,?,NULL,?,0,1,?,?,?)
                ON CONFLICT(guild_id,code) DO UPDATE SET
                    discount_percent=excluded.discount_percent,
                    product_id=NULL,
                    max_uses=excluded.max_uses,
                    used_count=0,
                    active=1,
                    expires_at=excluded.expires_at,
                    updated_at=excluded.updated_at
                """,
                (
                    i.guild.id,
                    coupon_code,
                    discount,
                    max_uses,
                    expires_db,
                    now_iso(),
                    now_iso(),
                ),
            )
            con.execute(
                "DELETE FROM cart_coupons WHERE guild_id=? AND coupon_code=?",
                (i.guild.id, coupon_code),
            )
            con.commit()
        finally:
            con.close()

        discord_timestamp = int(expires.timestamp())
        uses_text = "ilimitados" if max_uses is None else str(max_uses)
        await i.response.send_message(
            "✅ **Cupom geral liberado!**\n\n"
            f"🎟️ Código: `{coupon_code}`\n"
            f"💸 Desconto: **{discount:g}%**\n"
            "📦 Produtos: **todos os produtos da loja**\n"
            f"🔢 Usos: **{uses_text}**\n"
            f"⏳ Expira: <t:{discord_timestamp}:F> (<t:{discord_timestamp}:R>)",
            ephemeral=True,
        )


async def setup(bot, admin_check=None):
    global BOT, ADMIN_CHECK
    BOT = bot
    ADMIN_CHECK = admin_check
    init_db()

    # O botão "Gerar Key" continua respondendo mesmo após reiniciar o bot.
    try:
        bot.add_view(LicenseGenerateView())
    except Exception as exc:
        print(f"License persistent view: {exc}")

    for command_group in (
        CheckoutCommands(),
        CouponCommands(),
        AffiliateCommands(),
        MisticPayCommands(),
        LockSensiKeysCommands(),
    ):
        try:
            bot.tree.add_command(command_group)
        except app_commands.CommandAlreadyRegistered:
            pass
    if not getattr(bot, "_mistic_watcher", False):
        bot._mistic_watcher = True
        asyncio.create_task(watcher())


async def webhook_process(payload):
    tid = str(
        payload.get("transactionId")
        or (payload.get("transaction") or {}).get("transactionId")
        or (payload.get("data") or {}).get("transactionId")
        or ""
    )
    if not tid:
        return
    con = db()
    row = con.execute("SELECT id FROM orders WHERE transaction_id=?", (tid,)).fetchone()
    con.close()
    if row:
        await verify(row["id"])
