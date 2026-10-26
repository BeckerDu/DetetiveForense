# Agente LGPD para repositórios

Um agente que revisa código à procura de dados pessoais mal tratados e explica o risco com base na LGPD (Lei 13.709/2018). Roda no GitHub Actions: a cada pull request, toda segunda-feira de manhã, ou quando você mandar.

## O que ele faz

1. **Scanner** (`agent/lgpd_scan.py`): varre o código atrás de sinais como CPF (com validação dos dígitos), RG, telefone, e-mail, número de cartão (teste de Luhn), data de nascimento, campos que sugerem dado sensível (saúde, religião, biometria...), dados pessoais indo para log, senhas fixas no código, MD5/SHA-1 perto de senha e dados pessoais em URL.
2. **Revisor com IA** (`agent/lgpd_review.py`): manda os achados para a Claude, que separa o que é real do que é falso positivo, explica o risco em linguagem simples, cita os artigos da LGPD e sugere a correção. Também rascunha itens para o RIPD (relatório de impacto).
3. **Workflow** (`.github/workflows/lgpd-agent.yml`): executa tudo e comenta o relatório no pull request.

## Privacidade do próprio agente

- **Somente leitura.** Ele não altera seu código.
- **Tudo é mascarado antes de sair do scanner.** CPF vira `***.***.*89-09`, e-mail vira `j***@dominio.com`, e assim por diante. Nem o relatório nem o que vai para a IA contêm o dado real.
- **O código é tratado como não confiável.** O prompt instrui o modelo a ignorar qualquer "instrução" escondida em comentários ou strings do repositório analisado.
- **Permissões mínimas** no workflow: ler conteúdo e comentar em PR.
- Use apenas em repositórios seus ou com autorização. Se o repositório for de cliente, avalie antes se enviar trechos do código (mesmo mascarados) a um provedor de IA é compatível com o contrato e com a LGPD.

## Como instalar

1. Crie um repositório no GitHub (ou use um existente) e copie para ele estas pastas: `agent/` e `.github/workflows/`.
2. Em **Settings > Secrets and variables > Actions > New repository secret**, crie `ANTHROPIC_API_KEY` com sua chave da API da Anthropic (console.anthropic.com).
   Sem a chave o agente funciona mesmo assim, só que entrega o relatório do scanner, sem a revisão por IA.
3. Abra um pull request ou vá em **Actions > Agente LGPD > Run workflow** para testar.

Para testar localmente:

```bash
python agent/lgpd_scan.py --all --output findings.json
python agent/lgpd_review.py --findings findings.json --dry-run   # só mostra o prompt, não chama a API
ANTHROPIC_API_KEY=... python agent/lgpd_review.py --findings findings.json
```

## Ajustes úteis

- **Modelo:** defina a variável de ambiente `LGPD_MODEL` (padrão: `claude-sonnet-5-5`).
- **Bloquear merge:** no workflow, descomente o último passo para falhar quando houver achado de severidade alta.
- **Novas regras:** adicione um padrão em `agent/lgpd_scan.py` (tabela `RULES` e função `detect`).
- **Segurança extra:** troque as versões das actions (`@v4`, `@v5`) por SHAs fixos de commit.

## Limites que você precisa conhecer

- É um **detector de indícios**, não um auditor. Pode errar para os dois lados: falso positivo (CPF de teste) e falso negativo (dado pessoal que não segue nenhum padrão conhecido, como um nome numa coluna qualquer).
- Não olha o histórico do Git nem bancos de dados, só os arquivos do momento.
- A parte jurídica é **apoio**: não substitui análise de advogado nem o parecer do encarregado (DPO).

## Ideias para evoluir

- Gerar o rascunho completo do RIPD como arquivo `.md` no repositório.
- Mapear o fluxo do dado (onde entra, onde é guardado, para quem é enviado).
- Verificar política de retenção e de exclusão (direitos do titular, art. 18).
