import os, sqlite3, asyncio, json, io, random, string, traceback, re
from datetime import datetime
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
import qrcode

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
PIX_KEY = os.getenv('PIX_KEY','')
PIX_NOME = os.getenv('PIX_NOME','LOJA')[:25]
PIX_CIDADE = os.getenv('PIX_CIDADE','SAO PAULO')[:15]
WEBHOOK_URL = os.getenv('WEBHOOK_URL','')
OWNER_IDS = [int(x) for x in os.getenv('OWNER_IDS','').replace(';',',').split(',') if x.strip().isdigit()]
TICKET_IMAGE_URL = os.getenv('TICKET_IMAGE_URL','')
TICKET_THUMB_URL = os.getenv('TICKET_THUMB_URL','')
TICKET_CATEGORY_NAME = os.getenv('TICKET_CATEGORY_NAME','tickets')
TICKET_PANEL_TITLE = os.getenv('TICKET_PANEL_TITLE','🤖 Central de Suporte')
TICKET_PANEL_DESC = os.getenv('TICKET_PANEL_DESC','Olá! Bem-vindo ao nosso sistema de suporte.\n\n• Abra um ticket apenas se necessário\n• Respeite as regras do servidor\n• Nossa equipe responderá o mais rápido possível\n\nRenegade © Suporte Oficial')
DB = 'vendas.db'

if not TOKEN or TOKEN == 'COLE_SEU_TOKEN_AQUI':
    print('ERROR: coloque DISCORD_TOKEN no arquivo .env')
    raise SystemExit

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True
intents.voice_states = True
bot = commands.Bot(command_prefix='!', intents=intents)

# ================= HELPERS =================
def valid_url(url: Optional[str]) -> bool:
    if not url: return False
    url = str(url).strip()
    return bool(re.match(r'^https?://[^\s]+\.[^\s]+', url))

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def add_column_if_missing(cur, table, col, typ):
    cols = [r[1] for r in cur.execute(f'PRAGMA table_info({table})').fetchall()]
    if col not in cols:
        cur.execute(f'ALTER TABLE {table} ADD COLUMN {col} {typ}')

def init_db():
    con = db(); cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS guild_config(
        guild_id INTEGER PRIMARY KEY,
        log_channel_id INTEGER, sales_channel_id INTEGER, review_channel_id INTEGER,
        support_category_id INTEGER, customer_role_id INTEGER,
        pix_key TEXT, pix_name TEXT, pix_city TEXT, webhook_url TEXT,
        mp_token TEXT, efi_client_id TEXT, efi_client_secret TEXT,
        store_name TEXT DEFAULT 'Entregas automática', color INTEGER DEFAULT 5793266
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS products(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER, name TEXT, price REAL DEFAULT 0, stock INTEGER DEFAULT -1,
        description TEXT DEFAULT '', image_url TEXT DEFAULT '', banner_url TEXT DEFAULT '',
        delivery_text TEXT DEFAULT '', category TEXT DEFAULT 'Produtos', active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS panels(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER, name TEXT, title TEXT, description TEXT, image_url TEXT DEFAULT '', banner_url TEXT DEFAULT '',
        channel_id INTEGER, message_id INTEGER, topic_id INTEGER, color INTEGER DEFAULT 5793266,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS panel_products(panel_id INTEGER, product_id INTEGER, UNIQUE(panel_id, product_id))''')
    cur.execute('''CREATE TABLE IF NOT EXISTS orders(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER, user_id INTEGER, product_id INTEGER, product_name TEXT,
        amount REAL, status TEXT DEFAULT 'pendente', code TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, user_id INTEGER, stars INTEGER, text TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
    # Migração segura para versões antigas do banco
    for col, typ in [
        ('image_url','TEXT DEFAULT ""'), ('banner_url','TEXT DEFAULT ""'), ('delivery_text','TEXT DEFAULT ""'),
        ('category','TEXT DEFAULT "Produtos"'), ('active','INTEGER DEFAULT 1')
    ]:
        add_column_if_missing(cur, 'products', col, typ)
    for col, typ in [('image_url','TEXT DEFAULT ""'), ('banner_url','TEXT DEFAULT ""'), ('topic_id','INTEGER'), ('color','INTEGER DEFAULT 5793266')]:
        add_column_if_missing(cur, 'panels', col, typ)
    con.commit(); con.close()
init_db()

def ensure_config(guild_id:int):
    con=db(); cur=con.cursor()
    cur.execute('INSERT OR IGNORE INTO guild_config(guild_id,pix_key,pix_name,pix_city,webhook_url) VALUES(?,?,?,?,?)', (guild_id,PIX_KEY,PIX_NOME,PIX_CIDADE,WEBHOOK_URL))
    con.commit(); con.close()

def get_config(guild_id:int):
    ensure_config(guild_id)
    con=db(); row=con.execute('SELECT * FROM guild_config WHERE guild_id=?',(guild_id,)).fetchone(); con.close(); return row

def is_admin(inter:discord.Interaction):
    return inter.user.guild_permissions.administrator or inter.user.id in OWNER_IDS

async def admin_only(inter):
    if not is_admin(inter):
        await inter.response.send_message('❌ Apenas administradores podem usar isso.', ephemeral=True)
        return False
    return True

def money(v): return f'R${float(v):.2f}'.replace('.', ',')
def random_code(n=8): return ''.join(random.choice(string.ascii_uppercase+string.digits) for _ in range(n))

def pix_payload(key, name, city, amount, txid):
    return f'PIX|CHAVE:{key}|NOME:{name}|CIDADE:{city}|VALOR:{amount:.2f}|TXID:{txid}'

def make_qr_bytes(text):
    img = qrcode.make(text)
    bio = io.BytesIO(); img.save(bio, format='PNG'); bio.seek(0); return bio

async def log(guild:discord.Guild, msg:str):
    cfg=get_config(guild.id)
    ch = guild.get_channel(cfg['log_channel_id']) if cfg and cfg['log_channel_id'] else None
    if ch:
        try: await ch.send(msg)
        except Exception: pass

# ================= UI VENDAS =================
class BuyView(discord.ui.View):
    def __init__(self, product_id:int=None, panel_id:int=None):
        super().__init__(timeout=None)
        self.product_id=product_id; self.panel_id=panel_id
        if panel_id: self.add_item(PanelSelect(panel_id))

    @discord.ui.button(label='🛒 Comprar agora', style=discord.ButtonStyle.green, custom_id='buy_single_product')
    async def buy_btn(self, interaction:discord.Interaction, button:discord.ui.Button):
        if self.product_id: await start_order(interaction, self.product_id)
        else: await interaction.response.send_message('Selecione um produto no menu abaixo.', ephemeral=True)

class PanelOnlyView(discord.ui.View):
    def __init__(self, panel_id:int):
        super().__init__(timeout=None)
        self.add_item(PanelSelect(panel_id))

class PanelSelect(discord.ui.Select):
    def __init__(self, panel_id:int):
        self.panel_id=panel_id
        options=[]
        con=db()
        rows=con.execute('''SELECT p.* FROM products p JOIN panel_products pp ON p.id=pp.product_id WHERE pp.panel_id=? AND p.active=1 ORDER BY p.price ASC''',(panel_id,)).fetchall()
        con.close()
        for p in rows[:25]:
            stock = '∞' if p['stock'] < 0 else str(p['stock'])
            options.append(discord.SelectOption(label=p['name'][:100], description=f'{money(p["price"])} | Estoque: {stock}', emoji='🛒', value=str(p['id'])))
        if not options:
            options=[discord.SelectOption(label='Nenhum produto configurado', value='none', emoji='❌')]
        super().__init__(placeholder='Escolha uma opção...', min_values=1, max_values=1, options=options, custom_id=f'panel_select_{panel_id}')
    async def callback(self, interaction:discord.Interaction):
        if self.values[0]=='none':
            await interaction.response.send_message('Nenhum produto neste painel ainda.', ephemeral=True); return
        # Responde rápido para o Discord não derrubar a interação em hospedagem lenta
        await interaction.response.defer(ephemeral=True, thinking=True)
        await start_order(interaction, int(self.values[0]))

async def smart_send(interaction: discord.Interaction, *args, **kwargs):
    # Se a interação já recebeu defer(), usa followup. Senão, responde normal.
    if interaction.response.is_done():
        return await interaction.followup.send(*args, **kwargs)
    return await interaction.response.send_message(*args, **kwargs)

async def start_order(interaction:discord.Interaction, product_id:int):
    con=db(); p=con.execute('SELECT * FROM products WHERE id=?',(product_id,)).fetchone()
    if not p:
        con.close(); await smart_send(interaction, '❌ Produto não encontrado.', ephemeral=True); return
    if p['stock']==0:
        con.close(); await smart_send(interaction, '❌ Produto sem estoque.', ephemeral=True); return
    code=random_code()
    con.execute('INSERT INTO orders(guild_id,user_id,product_id,product_name,amount,code) VALUES(?,?,?,?,?,?)',(interaction.guild.id, interaction.user.id, product_id, p['name'], p['price'], code))
    con.commit(); oid=con.execute('SELECT last_insert_rowid()').fetchone()[0]; con.close()
    cfg=get_config(interaction.guild.id)
    pix_key = cfg['pix_key'] or PIX_KEY
    if not pix_key:
        await smart_send(interaction, '❌ PIX ainda não configurado. Use /autenticacao ou /configurar.', ephemeral=True); return
    payload = pix_payload(pix_key, cfg['pix_name'] or PIX_NOME, cfg['pix_city'] or PIX_CIDADE, p['price'], code)
    qr=make_qr_bytes(payload); file=discord.File(qr, filename='pix.png')
    embed=discord.Embed(title=f'💎 Pedido #{oid} - {p["name"]}', description='Pague usando o QR Code ou copia e cola abaixo.', color=0x00a86b)
    embed.add_field(name='💰 Valor', value=money(p['price']), inline=True)
    embed.add_field(name='🔑 Código', value=code, inline=True)
    embed.add_field(name='📋 PIX copia e cola', value=f'```{payload[:900]}```', inline=False)
    embed.set_image(url='attachment://pix.png')
    await smart_send(interaction, embed=embed, file=file, ephemeral=True)
    await log(interaction.guild, f'🛒 Novo pedido #{oid}: {interaction.user.mention} comprou **{p["name"]}** por {money(p["price"])}')

# ================= EMBEDS =================
def product_embed(p):
    stock='∞' if p['stock'] < 0 else str(p['stock'])
    embed=discord.Embed(title=f'💎 {p["name"]}', description=p['description'] or 'Produto sem descrição.', color=0x5865F2)
    embed.add_field(name='💰 Preço', value=money(p['price']), inline=True)
    embed.add_field(name='📦 Estoque', value=stock, inline=True)
    embed.add_field(name='⚡ Entrega', value='Automática após aprovação', inline=False)
    if valid_url(p['image_url']): embed.set_thumbnail(url=p['image_url'])
    if valid_url(p['banner_url']): embed.set_image(url=p['banner_url'])
    embed.set_footer(text='Entregas automática • Hoje')
    return embed

def panel_embed(panel_id:int):
    con=db(); panel=con.execute('SELECT * FROM panels WHERE id=?',(panel_id,)).fetchone(); con.close()
    if not panel:
        return discord.Embed(title='Painel não encontrado', color=0xff0000)
    # CORREÇÃO PEDIDA: NÃO mostra valores/planos dentro da descrição.
    embed=discord.Embed(title=panel['title'] or panel['name'], description=(panel['description'] or '')[:4096], color=panel['color'] or 0x5865F2)
    if valid_url(panel['image_url']): embed.set_thumbnail(url=panel['image_url'])
    if valid_url(panel['banner_url']): embed.set_image(url=panel['banner_url'])
    embed.set_footer(text='Entregas automática • Painel de vendas')
    return embed

# ================= MODALS PAINEL =================
class PanelTextModal(discord.ui.Modal, title='Configurar painel'):
    def __init__(self, panel_id:int):
        super().__init__(); self.panel_id=panel_id
        con=db(); p=con.execute('SELECT * FROM panels WHERE id=?',(panel_id,)).fetchone(); con.close()
        self.titulo=discord.ui.TextInput(label='Título', default=p['title'] or p['name'], max_length=100)
        self.desc=discord.ui.TextInput(label='Descrição', default=p['description'] or '', style=discord.TextStyle.paragraph, required=False, max_length=3000)
        self.img=discord.ui.TextInput(label='Thumbnail/Imagem pequena URL', default=p['image_url'] or '', required=False)
        self.banner=discord.ui.TextInput(label='Banner/Imagem grande URL', default=p['banner_url'] or '', required=False)
        self.add_item(self.titulo); self.add_item(self.desc); self.add_item(self.img); self.add_item(self.banner)
    async def on_submit(self, interaction):
        con=db(); con.execute('UPDATE panels SET title=?,description=?,image_url=?,banner_url=? WHERE id=?',(str(self.titulo),str(self.desc),str(self.img),str(self.banner),self.panel_id)); con.commit(); con.close()
        await interaction.response.send_message('✅ Painel atualizado.', ephemeral=True)

class PlanModal(discord.ui.Modal, title='Adicionar plano/produto'):
    def __init__(self, panel_id:int):
        super().__init__(); self.panel_id=panel_id
        self.nome=discord.ui.TextInput(label='Nome do plano', placeholder='Bypass Mensal')
        self.preco=discord.ui.TextInput(label='Preço', placeholder='45.00')
        self.estoque=discord.ui.TextInput(label='Estoque (-1 para infinito)', default='-1')
        self.desc=discord.ui.TextInput(label='Descrição/entrega', required=False, style=discord.TextStyle.paragraph)
        self.add_item(self.nome); self.add_item(self.preco); self.add_item(self.estoque); self.add_item(self.desc)
    async def on_submit(self, interaction):
        try: price=float(str(self.preco).replace(',','.')); stock=int(str(self.estoque))
        except Exception:
            await interaction.response.send_message('❌ Preço ou estoque inválido.', ephemeral=True); return
        con=db(); cur=con.cursor()
        cur.execute('INSERT INTO products(guild_id,name,price,stock,description,category,delivery_text) VALUES(?,?,?,?,?,?,?)',(interaction.guild.id,str(self.nome),price,stock,str(self.desc),'Painel',str(self.desc)))
        pid=cur.lastrowid; cur.execute('INSERT OR IGNORE INTO panel_products(panel_id,product_id) VALUES(?,?)',(self.panel_id,pid)); con.commit(); con.close()
        await interaction.response.send_message(f'✅ Plano **{self.nome}** adicionado ao painel.', ephemeral=True)

class ConfigPanelView(discord.ui.View):
    def __init__(self, panel_id:int):
        super().__init__(timeout=None); self.panel_id=panel_id
    @discord.ui.button(label='✏️ Texto/Imagem', style=discord.ButtonStyle.blurple)
    async def text_img(self, interaction, button): await interaction.response.send_modal(PanelTextModal(self.panel_id))
    @discord.ui.button(label='➕ Adicionar plano', style=discord.ButtonStyle.green)
    async def add_plan(self, interaction, button): await interaction.response.send_modal(PlanModal(self.panel_id))
    @discord.ui.button(label='👁️ Prévia', style=discord.ButtonStyle.gray)
    async def preview(self, interaction, button): await interaction.response.send_message(embed=panel_embed(self.panel_id), view=PanelOnlyView(self.panel_id), ephemeral=True)
    @discord.ui.button(label='🚀 Publicar aqui', style=discord.ButtonStyle.red)
    async def publish_here(self, interaction, button):
        await interaction.channel.send(embed=panel_embed(self.panel_id), view=PanelOnlyView(self.panel_id))
        await interaction.response.send_message('✅ Painel publicado neste canal/tópico.', ephemeral=True)

# ================= TICKET =================
def ticket_panel_embed(titulo=None, descricao=None, imagem=None, thumb=None):
    embed = discord.Embed(
        title=titulo or TICKET_PANEL_TITLE,
        description=descricao or TICKET_PANEL_DESC,
        color=0x5865F2
    )
    # CORREÇÃO: só aplica URL se for válida. Evita Invalid Form Body.
    img = imagem or TICKET_IMAGE_URL
    th = thumb or TICKET_THUMB_URL
    if valid_url(th): embed.set_thumbnail(url=th)
    if valid_url(img): embed.set_image(url=img)
    embed.set_footer(text='Renegade Support • Atendimento profissional')
    return embed

class CloseTicketView(discord.ui.View):
    def __init__(self): super().__init__(timeout=None)
    @discord.ui.button(label='🔒 Fechar Ticket', style=discord.ButtonStyle.danger, custom_id='close_ticket_v13')
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message('🔒 Ticket será fechado em 5 segundos...', ephemeral=True)
        await asyncio.sleep(5)
        try: await interaction.channel.delete()
        except Exception: pass

class TicketPanelView(discord.ui.View):
    def __init__(self): super().__init__(timeout=None)
    @discord.ui.button(label='📩 Suporte', style=discord.ButtonStyle.primary, custom_id='ticket_suporte_v13')
    async def suporte(self, interaction: discord.Interaction, button: discord.ui.Button): await criar_ticket(interaction, 'suporte')
    @discord.ui.button(label='❓ Dúvidas', style=discord.ButtonStyle.secondary, custom_id='ticket_duvidas_v13')
    async def duvidas(self, interaction: discord.Interaction, button: discord.ui.Button): await criar_ticket(interaction, 'duvidas')
    @discord.ui.button(label='💰 Financeiro', style=discord.ButtonStyle.success, custom_id='ticket_financeiro_v13')
    async def financeiro(self, interaction: discord.Interaction, button: discord.ui.Button): await criar_ticket(interaction, 'financeiro')

async def criar_ticket(interaction: discord.Interaction, tipo: str):
    await interaction.response.defer(ephemeral=True)
    guild=interaction.guild; user=interaction.user
    category = discord.utils.get(guild.categories, name=TICKET_CATEGORY_NAME)
    if not category: category = await guild.create_category(TICKET_CATEGORY_NAME)
    overwrites={
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        user: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True)
    }
    ch = await guild.create_text_channel(f'{tipo}-{user.name}'[:90], category=category, overwrites=overwrites)
    embed = discord.Embed(title='📁 Ticket aberto', description=f'👋 {user.mention}, bem-vindo ao **Renegade Suporte**\n\n📌 **Tipo:** {tipo.upper()}\n\nExplique seu problema abaixo.', color=0x2b2d31)
    await ch.send(embed=embed, view=CloseTicketView())
    await interaction.followup.send(f'✅ Ticket criado: {ch.mention}', ephemeral=True)

# ================= COMMANDS =================
@bot.event
async def on_ready():
    init_db()

    # Persistent views: mantém botões/dropdowns funcionando após reiniciar o bot.
    # Isso restaura todos os painéis salvos no vendas.db.
    bot.add_view(TicketPanelView())
    bot.add_view(CloseTicketView())
    try:
        con = db()
        paineis = con.execute('SELECT id FROM panels').fetchall()
        con.close()
        for painel in paineis:
            try:
                bot.add_view(PanelOnlyView(int(painel['id'])))
            except Exception as e:
                print('erro restaurando painel', painel['id'], e)
        print(f'Views persistentes restauradas: {len(paineis)} painel(is)')
    except Exception as e:
        print('Erro restaurando views persistentes:', e)

    for g in bot.guilds: ensure_config(g.id)
    try:
        global_synced = await bot.tree.sync()
        total=0
        for g in bot.guilds:
            try:
                bot.tree.copy_global_to(guild=g)
                s=await bot.tree.sync(guild=g); total += len(s)
            except Exception as e: print('sync guild erro', g.id, e)
        print(f'Online como {bot.user}')
        print(f'Comandos globais: {len(global_synced)} | comandos em servidores: {total}')
    except Exception as e: print('Erro sync:', e)

@bot.tree.command(name='sincronizar', description='Força sincronização dos slash commands')
async def sincronizar(interaction:discord.Interaction):
    if not await admin_only(interaction): return
    await bot.tree.sync(); bot.tree.copy_global_to(guild=interaction.guild); cmds=await bot.tree.sync(guild=interaction.guild)
    await interaction.response.send_message(f'✅ Comandos sincronizados: {len(cmds)}. Aperte Ctrl+R no Discord.', ephemeral=True)

@bot.tree.command(name='ping', description='Mostra o ping do bot')
async def ping(interaction): await interaction.response.send_message(f'🏓 Pong! `{round(bot.latency*1000)}ms`', ephemeral=True)

@bot.tree.command(name='configurar', description='Cria estrutura inicial do bot')
async def configurar(interaction):
    if not await admin_only(interaction): return
    guild=interaction.guild; ensure_config(guild.id)
    cat=await guild.create_category('🛒 Loja / Vendas')
    painel=await guild.create_text_channel('🛒・seu-painel', category=cat)
    logs=await guild.create_text_channel('📋・logs-vendas', category=cat)
    aval=await guild.create_text_channel('⭐・avaliações', category=cat)
    role=discord.utils.get(guild.roles, name='Cliente') or await guild.create_role(name='Cliente')
    con=db(); con.execute('UPDATE guild_config SET sales_channel_id=?,log_channel_id=?,review_channel_id=?,support_category_id=?,customer_role_id=? WHERE guild_id=?',(painel.id,logs.id,aval.id,cat.id,role.id,guild.id)); con.commit(); con.close()
    await interaction.response.send_message(f'✅ Configurado: {painel.mention}, {logs.mention}, {aval.mention}', ephemeral=True)

@bot.tree.command(name='autenticacao', description='Configura Pix, Mercado Pago, EFI e webhook')
@app_commands.describe(pix_key='Chave PIX', pix_nome='Nome recebedor', pix_cidade='Cidade', mercado_pago_token='Access token MP', webhook='Webhook de logs')
async def autenticacao(interaction, pix_key:Optional[str]=None, pix_nome:Optional[str]=None, pix_cidade:Optional[str]=None, mercado_pago_token:Optional[str]=None, webhook:Optional[str]=None):
    if not await admin_only(interaction): return
    ensure_config(interaction.guild.id)
    con=db(); cfg=get_config(interaction.guild.id)
    con.execute('UPDATE guild_config SET pix_key=?, pix_name=?, pix_city=?, mp_token=?, webhook_url=? WHERE guild_id=?', (pix_key or cfg['pix_key'], pix_nome or cfg['pix_name'], pix_cidade or cfg['pix_city'], mercado_pago_token or cfg['mp_token'], webhook or cfg['webhook_url'], interaction.guild.id)); con.commit(); con.close()
    await interaction.response.send_message('✅ Autenticação/PIX atualizados.', ephemeral=True)

@bot.tree.command(name='webhook', description='Cadastra webhook para logs')
async def webhook(interaction, url:str):
    if not await admin_only(interaction): return
    con=db(); ensure_config(interaction.guild.id); con.execute('UPDATE guild_config SET webhook_url=? WHERE guild_id=?',(url,interaction.guild.id)); con.commit(); con.close()
    await interaction.response.send_message('✅ Webhook salvo.', ephemeral=True)

@bot.tree.command(name='saldo', description='Exibe saldo/configuração de pagamento')
async def saldo(interaction):
    cfg=get_config(interaction.guild.id)
    await interaction.response.send_message(f'💰 PIX configurado: `{bool(cfg["pix_key"])}`\nMercado Pago: `{bool(cfg["mp_token"])}`', ephemeral=True)

@bot.tree.command(name='cargo_id', description='Mostra o ID de um cargo')
async def cargo_id(interaction, cargo:discord.Role): await interaction.response.send_message(f'Cargo {cargo.mention} ID: `{cargo.id}`', ephemeral=True)

@bot.tree.command(name='canal-de-avaliacoes', description='Seleciona canal para avaliações')
async def canal_de_avaliacoes(interaction, canal:discord.TextChannel):
    if not await admin_only(interaction): return
    ensure_config(interaction.guild.id); con=db(); con.execute('UPDATE guild_config SET review_channel_id=? WHERE guild_id=?',(canal.id, interaction.guild.id)); con.commit(); con.close()
    await interaction.response.send_message(f'✅ Canal de avaliações: {canal.mention}', ephemeral=True)

@bot.tree.command(name='avaliacoes-servidor', description='Mostra média de avaliações')
async def avaliacoes_servidor(interaction):
    con=db(); rows=con.execute('SELECT stars FROM reviews WHERE guild_id=?',(interaction.guild.id,)).fetchall(); con.close()
    if not rows: await interaction.response.send_message('⭐ Ainda não há avaliações.', ephemeral=True); return
    avg=sum(r['stars'] for r in rows)/len(rows)
    await interaction.response.send_message(f'⭐ Média: **{avg:.1f}/5** em **{len(rows)}** avaliações.', ephemeral=True)

@bot.tree.command(name='criar-painel-config', description='Abre tópico/painel para configurar produto por botões')
@app_commands.describe(nome='Nome interno do painel')
async def criar_painel_config(interaction, nome:str):
    if not await admin_only(interaction): return
    con=db(); cur=con.cursor(); cur.execute('INSERT INTO panels(guild_id,name,title,description,channel_id) VALUES(?,?,?,?,?)',(interaction.guild.id,nome,nome,'Configure a descrição deste painel clicando nos botões abaixo.', interaction.channel.id)); panel_id=cur.lastrowid; con.commit(); con.close()
    await interaction.response.send_message(f'✅ Painel criado. ID `{panel_id}`', ephemeral=True)
    msg=await interaction.channel.send(f'⚙️ Configuração do painel **{nome}**\nID: `{panel_id}`', view=ConfigPanelView(panel_id))
    try:
        thread=await msg.create_thread(name=f'config-{nome}'[:90])
        await thread.send('Use os botões acima para configurar texto, imagem, banner e planos. Depois clique em publicar aqui.')
        con=db(); con.execute('UPDATE panels SET topic_id=? WHERE id=?',(thread.id,panel_id)); con.commit(); con.close()
    except Exception: pass

@bot.tree.command(name='adicionar-plano', description='Adiciona plano/produto a um painel existente')
async def adicionar_plano(interaction, painel_id:int, nome:str, preco:float, estoque:int=-1, descricao:str=''):
    if not await admin_only(interaction): return
    con=db(); cur=con.cursor(); cur.execute('INSERT INTO products(guild_id,name,price,stock,description,category,delivery_text) VALUES(?,?,?,?,?,?,?)',(interaction.guild.id,nome,preco,estoque,descricao,'Painel',descricao)); pid=cur.lastrowid; cur.execute('INSERT OR IGNORE INTO panel_products(panel_id,product_id) VALUES(?,?)',(painel_id,pid)); con.commit(); con.close()
    await interaction.response.send_message(f'✅ Plano `{nome}` adicionado ao painel `{painel_id}`.', ephemeral=True)

@bot.tree.command(name='publicar-painel', description='Publica painel de produtos no canal')
async def publicar_painel(interaction, painel_id:int, canal:Optional[discord.TextChannel]=None):
    if not await admin_only(interaction): return
    canal=canal or interaction.channel
    msg=await canal.send(embed=panel_embed(painel_id), view=PanelOnlyView(painel_id))
    con=db(); con.execute('UPDATE panels SET channel_id=?,message_id=? WHERE id=?',(canal.id,msg.id,painel_id)); con.commit(); con.close()
    await interaction.response.send_message(f'✅ Painel publicado em {canal.mention}', ephemeral=True)

@bot.tree.command(name='criar-produto-canal-atual', description='Cria produto único no canal atual')
async def criar_produto_canal_atual(interaction, nome:str, preco:float, estoque:int, descricao:str, imagem:Optional[str]=None, banner:Optional[str]=None):
    if not await admin_only(interaction): return
    con=db(); cur=con.cursor(); cur.execute('INSERT INTO products(guild_id,name,price,stock,description,image_url,banner_url) VALUES(?,?,?,?,?,?,?)',(interaction.guild.id,nome,preco,estoque,descricao,imagem or '',banner or '')); pid=cur.lastrowid; p=con.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone(); con.commit(); con.close()
    await interaction.channel.send(embed=product_embed(p), view=BuyView(product_id=pid))
    await interaction.response.send_message('✅ Produto criado no canal atual.', ephemeral=True)

@bot.tree.command(name='criar-produto-lista', description='Cria produto e adiciona em painel/lista')
async def criar_produto_lista(interaction, painel_id:int, nome:str, preco:float, estoque:int=-1, descricao:str='', imagem:Optional[str]=None, banner:Optional[str]=None):
    if not await admin_only(interaction): return
    con=db(); cur=con.cursor(); cur.execute('INSERT INTO products(guild_id,name,price,stock,description,image_url,banner_url) VALUES(?,?,?,?,?,?,?)',(interaction.guild.id,nome,preco,estoque,descricao,imagem or '',banner or '')); pid=cur.lastrowid; cur.execute('INSERT OR IGNORE INTO panel_products(panel_id,product_id) VALUES(?,?)',(painel_id,pid)); con.commit(); con.close()
    await interaction.response.send_message(f'✅ Produto `{nome}` adicionado ao painel `{painel_id}`.', ephemeral=True)

@bot.tree.command(name='editar-produto', description='Edita produto')
async def editar_produto(interaction, produto_id:int, nome:Optional[str]=None, preco:Optional[float]=None, estoque:Optional[int]=None, descricao:Optional[str]=None, imagem:Optional[str]=None, banner:Optional[str]=None):
    if not await admin_only(interaction): return
    con=db(); p=con.execute('SELECT * FROM products WHERE id=?',(produto_id,)).fetchone()
    if not p: con.close(); await interaction.response.send_message('❌ Produto não encontrado.', ephemeral=True); return
    con.execute('UPDATE products SET name=?,price=?,stock=?,description=?,image_url=?,banner_url=? WHERE id=?',(nome or p['name'], preco if preco is not None else p['price'], estoque if estoque is not None else p['stock'], descricao if descricao is not None else p['description'], imagem if imagem is not None else p['image_url'], banner if banner is not None else p['banner_url'], produto_id)); con.commit(); con.close()
    await interaction.response.send_message('✅ Produto editado.', ephemeral=True)

@bot.tree.command(name='remover-produto', description='Desativa produto')
async def remover_produto(interaction, produto_id:int):
    if not await admin_only(interaction): return
    con=db(); con.execute('UPDATE products SET active=0 WHERE id=?',(produto_id,)); con.commit(); con.close()
    await interaction.response.send_message('✅ Produto removido/desativado.', ephemeral=True)

@bot.tree.command(name='cobrar', description='Cria cobrança PIX personalizada')
async def cobrar(interaction, valor:float, descricao:str='Cobrança personalizada'):
    code=random_code(); cfg=get_config(interaction.guild.id); key=cfg['pix_key'] or PIX_KEY
    if not key: await interaction.response.send_message('❌ Configure PIX primeiro.', ephemeral=True); return
    payload=pix_payload(key,cfg['pix_name'] or PIX_NOME,cfg['pix_city'] or PIX_CIDADE,valor,code)
    file=discord.File(make_qr_bytes(payload), filename='pix.png')
    embed=discord.Embed(title='💰 Cobrança PIX', description=descricao, color=0x00a86b)
    embed.add_field(name='Valor', value=money(valor)); embed.add_field(name='Código', value=code)
    embed.add_field(name='Copia e cola', value=f'```{payload[:900]}```', inline=False); embed.set_image(url='attachment://pix.png')
    await interaction.response.send_message(embed=embed, file=file, ephemeral=True)

@bot.tree.command(name='estatisticas', description='Mostra estatísticas de vendas')
async def estatisticas(interaction):
    con=db(); rows=con.execute('SELECT * FROM orders WHERE guild_id=?',(interaction.guild.id,)).fetchall(); con.close()
    total=sum(r['amount'] for r in rows); pend=sum(1 for r in rows if r['status']=='pendente'); ok=sum(1 for r in rows if r['status']=='aprovado')
    embed=discord.Embed(title='💫 Seus rendimentos durante:', color=0x2b2d31)
    embed.add_field(name='💎 Pedidos', value=str(len(rows)), inline=True); embed.add_field(name='💰 Recebimentos', value=money(total), inline=True)
    embed.add_field(name='⏳ Pendentes', value=str(pend), inline=True); embed.add_field(name='✅ Aprovados', value=str(ok), inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name='conectar', description='Conecta o bot em um canal de voz')
async def conectar(interaction, canal:Optional[discord.VoiceChannel]=None):
    # Defer imediato evita Unknown interaction quando a conexão de voz demora.
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        canal = canal or (interaction.user.voice.channel if interaction.user.voice else None)
        if not canal:
            await interaction.followup.send('❌ Entre em uma call ou escolha um canal.', ephemeral=True)
            return
        if interaction.guild.voice_client:
            await interaction.guild.voice_client.move_to(canal)
        else:
            await canal.connect(timeout=30, reconnect=True, self_deaf=True)
        await interaction.followup.send(f'✅ Conectado em {canal.mention}', ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f'❌ Erro ao conectar: `{e}`', ephemeral=True)

@bot.tree.command(name='desconectar', description='Desconecta do canal de voz')
async def desconectar(interaction):
    try:
        if interaction.guild.voice_client: await interaction.guild.voice_client.disconnect(force=True); await interaction.response.send_message('✅ Desconectado.', ephemeral=True)
        else: await interaction.response.send_message('❌ Não estou em call.', ephemeral=True)
    except Exception as e: await interaction.response.send_message(f'❌ Erro: `{e}`', ephemeral=True)

@bot.tree.command(name='painel-ticket', description='Envia painel de ticket com imagem opcional')
@app_commands.describe(titulo='Título do painel', descricao='Descrição do painel', imagem='URL da imagem/banner')
async def painel_ticket(interaction, titulo:Optional[str]=None, descricao:Optional[str]=None, imagem:Optional[str]=None):
    if not await admin_only(interaction): return
    await interaction.response.defer(ephemeral=True)
    embed = ticket_panel_embed(titulo, descricao, imagem)
    await interaction.channel.send(embed=embed, view=TicketPanelView())
    await interaction.followup.send('✅ Painel de ticket enviado.', ephemeral=True)

@bot.tree.command(name='criar-tickets-modo-canais', description='Cria painel de ticket por canais')
async def criar_tickets_modo_canais(interaction):
    if not await admin_only(interaction): return
    await interaction.response.defer(ephemeral=True)
    await interaction.channel.send(embed=ticket_panel_embed(), view=TicketPanelView())
    await interaction.followup.send('✅ Painel de ticket enviado.', ephemeral=True)

@bot.tree.command(name='criar-tickets-modo-topico', description='Cria painel de ticket por tópico')
async def criar_tickets_modo_topico(interaction):
    if not await admin_only(interaction): return
    await interaction.response.defer(ephemeral=True)
    await interaction.channel.send(embed=ticket_panel_embed(), view=TicketPanelView())
    await interaction.followup.send('✅ Painel de ticket enviado.', ephemeral=True)

@bot.tree.command(name='criar-categoria', description='Cria categoria da loja')
async def criar_categoria(interaction, nome:str):
    if not await admin_only(interaction): return
    cat=await interaction.guild.create_category(nome); await interaction.response.send_message(f'✅ Categoria criada: `{cat.name}`', ephemeral=True)

@bot.tree.command(name='criar-painel-captcha', description='Cria painel simples de captcha/verificação')
async def criar_painel_captcha(interaction):
    if not await admin_only(interaction): return
    await interaction.channel.send(embed=discord.Embed(title='✅ Verificação', description='Clique para liberar acesso.', color=0x00ff99), view=CaptchaView())
    await interaction.response.send_message('✅ Painel captcha enviado.', ephemeral=True)

class CaptchaView(discord.ui.View):
    def __init__(self): super().__init__(timeout=None)
    @discord.ui.button(label='✅ Verificar', style=discord.ButtonStyle.green)
    async def verify(self, interaction, button): await interaction.response.send_message('✅ Verificado.', ephemeral=True)

@bot.tree.command(name='limpar', description='Apaga mensagens')
async def limpar(interaction, quantidade:int):
    if not await admin_only(interaction): return
    await interaction.response.defer(ephemeral=True); deleted=await interaction.channel.purge(limit=min(quantidade,100)); await interaction.followup.send(f'✅ Apaguei {len(deleted)} mensagens.', ephemeral=True)

@bot.tree.command(name='enviar-mensagem-servidor', description='Envia mensagem em canal selecionado')
async def enviar_mensagem_servidor(interaction, canal:discord.TextChannel, mensagem:str):
    if not await admin_only(interaction): return
    await canal.send(mensagem); await interaction.response.send_message('✅ Mensagem enviada.', ephemeral=True)

@bot.tree.command(name='enviar-mensagem-dm', description='Envia DM para usuário')
async def enviar_mensagem_dm(interaction, usuario:discord.Member, mensagem:str):
    if not await admin_only(interaction): return
    try: await usuario.send(mensagem); await interaction.response.send_message('✅ DM enviada.', ephemeral=True)
    except Exception as e: await interaction.response.send_message(f'❌ Erro: `{e}`', ephemeral=True)

@bot.tree.command(name='status-adicionar', description='Adiciona status/atividade no bot')
async def status_adicionar(interaction, texto:str):
    if not await admin_only(interaction): return
    await bot.change_presence(activity=discord.Game(name=texto)); await interaction.response.send_message('✅ Status alterado.', ephemeral=True)

@bot.tree.command(name='status-remover', description='Remove status do bot')
async def status_remover(interaction):
    if not await admin_only(interaction): return
    await bot.change_presence(activity=None); await interaction.response.send_message('✅ Status removido.', ephemeral=True)

@bot.tree.command(name='desbloquear', description='Desbloqueia comandos no canal atual')
async def desbloquear(interaction):
    if not await admin_only(interaction): return
    await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=True)
    await interaction.response.send_message('✅ Canal desbloqueado.', ephemeral=True)

@bot.tree.command(name='restaurar-servidor', description='Restaura dados básicos do servidor no banco')
async def restaurar_servidor(interaction):
    if not await admin_only(interaction): return
    ensure_config(interaction.guild.id); await interaction.response.send_message('✅ Dados restaurados/sincronizados no banco.', ephemeral=True)

bot.run(TOKEN)
