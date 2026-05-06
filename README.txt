BOT VENDAS PRO V14 - PERSISTENT FINAL

CORREÇÃO PRINCIPAL:
- Dropdowns e botões de comprar continuam funcionando depois de reiniciar o bot.
- Painéis e produtos são restaurados do vendas.db no on_ready.
- Produtos continuam salvos, não apague vendas.db.

COMO USAR:
1) Renomeie .env.example para .env
2) Coloque seu DISCORD_TOKEN e PIX_KEY
3) Instale:
   py -3.11 -m pip install -U -r requirements.txt
4) Rode:
   py -3.11 bot.py

IMPORTANTE:
- Se você já tinha produtos/painéis em outra pasta, copie o arquivo vendas.db antigo para esta pasta nova.
- Depois de adicionar plano novo em um painel já publicado, publique o painel novamente para atualizar o dropdown.
