# Sprint 2 — Histórias de usuário e testes

**Projeto:** LogSentinel — Analisador de logs e identificação de atividades suspeitas

Os testes estão em `test_logsentinel.py`, são 36 testes. O ID do critério (ex.: CA01.2) aparece no nome e na docstring de cada teste. Nesta sprint os testes falham de propósito, porque as funções ainda não foram implementadas.

## US01 — Falhas repetidas de login SSH

**Como** administrador de um pequeno servidor, **quero** que o sistema identifique IPs com falhas repetidas de autenticação SSH em pouco tempo, **para** perceber tentativas de força bruta sem ler o log linha a linha.

Critérios de aceitação:

- **CA01.1** — Uma linha `Failed password` (inclusive `invalid user`) tem o IP e o horário extraídos corretamente.
- **CA01.2** — Um IP com número de falhas maior ou igual ao limite dentro da janela de tempo gera exatamente 1 alerta.
- **CA01.3** — Um IP com falhas abaixo do limite não gera alerta, e falhas de IPs diferentes não são somadas.
- **CA01.4** — Falhas do mesmo IP separadas por mais que a janela de tempo não são somadas.
- **CA01.5** — Logins bem-sucedidos (`Accepted password`) não contam como falha.

## US02 — Excesso de respostas 404 no log web

**Como** desenvolvedor que hospeda um site, **quero** identificar IPs com muitas respostas 404 em pouco tempo, **para** detectar varreduras em busca de páginas escondidas.

Critérios de aceitação:

- **CA02.1** — Uma linha no formato Combined (Apache) tem IP, horário, caminho e status extraídos corretamente.
- **CA02.2** — Um IP com número de respostas 404 maior ou igual ao limite dentro da janela gera exatamente 1 alerta.
- **CA02.3** — Respostas com outros status (200, 500 etc.) não entram na contagem de 404.
- **CA02.4** — O alerta lista os caminhos acessados como evidência.

## US03 — Relatório com evidências

**Como** administrador, **quero** um relatório com IP, período, ocorrências, motivo e nível de suspeita, **para** decidir quais IPs vale a pena investigar.

Critérios de aceitação:

- **CA03.1** — Cada alerta aparece no relatório com IP, período, número de ocorrências, motivo e nível (formato `N/10`).
- **CA03.2** — O nível é um número inteiro de 1 a 10 e nunca diminui quando o número de ocorrências aumenta.
- **CA03.3** — Os alertas aparecem ordenados do maior para o menor nível.
- **CA03.4** — Quando não há alertas, o relatório informa "Nenhuma atividade suspeita".

## US04 — Arquivo de entrada informado na linha de comando

**Como** administrador, **quero** informar o arquivo de log a ser analisado ao rodar o programa, **para** analisar qualquer log sem mexer no código e tendo clareza de qual arquivo foi usado.

Critérios de aceitação:

- **CA04.1** — Os caminhos são informados por `--ssh caminho_arquivo` e/ou `--web caminho_arquivo`. O programa aceita somente SSH, somente web ou ambos na mesma execução, imprime o relatório no terminal e termina com código 0.
- **CA04.2** — A análise usa o conteúdo do arquivo informado: arquivos diferentes geram relatórios diferentes.
- **CA04.3** — Se o arquivo não existe, o programa mostra uma mensagem clara (com o caminho) no stderr, sem traceback, e termina com código diferente de 0.
- **CA04.4** — Se nenhum arquivo é informado, o programa mostra o modo de uso e termina com código diferente de 0.
- **CA04.5** — Linhas fora de qualquer formato conhecido são ignoradas sem interromper a análise, e o relatório informa quantas foram ignoradas.

Exemplo de uso previsto:

```text
python main.py --ssh data/OpenSSH_2k.log --web data/apache_logs.txt
```

## Relação entre testes e critérios

| Critério | Teste(s) |
|---|---|
| CA01.1 | `test_ca01_1_extrai_ip_de_falha_ssh`, `test_ca01_1_extrai_ip_de_usuario_invalido` |
| CA01.2 | `test_ca01_2_alerta_ao_atingir_limite_na_janela`, `test_dataset_ca01_2_alertas_com_limite_padrao`, `test_dataset_ca01_2_ocorrencias_respeitam_o_limite`, `test_dataset_ca01_2_limite_maior_reduz_os_alertas` |
| CA01.3 | `test_ca01_3_sem_alerta_abaixo_do_limite`, `test_ca01_3_ips_diferentes_nao_sao_somados` |
| CA01.4 | `test_ca01_4_falhas_fora_da_janela_nao_sao_somadas` |
| CA01.5 | `test_ca01_5_login_com_sucesso_nao_conta_como_falha`, `test_ca01_5_parser_identifica_login_com_sucesso` |
| CA02.1 | `test_ca02_1_extrai_campos_dos_formatos_de_acesso`, `test_dataset_web_ca02_1_extrai_campos_do_acesso` |
| CA02.2 | `test_ca02_2_alerta_ao_atingir_limite_de_404`, `test_dataset_web_ca02_2_alerta_com_limite_padrao` |
| CA02.3 | `test_ca02_3_outros_status_nao_contam` |
| CA02.4 | `test_ca02_4_alerta_traz_caminhos_como_evidencia` |
| CA03.1 | `test_ca03_1_relatorio_mostra_campos_do_alerta`, `test_ca03_1_relatorio_ponta_a_ponta`, `test_dataset_ca03_1_relatorio_cita_o_ip_mais_agressivo` |
| CA03.2 | `test_ca03_2_nivel_entre_1_e_10_e_nao_decrescente` |
| CA03.3 | `test_ca03_3_alertas_ordenados_do_maior_para_o_menor_nivel`, `test_dataset_ca03_3_ip_mais_agressivo_vem_primeiro` |
| CA03.4 | `test_ca03_4_relatorio_sem_alertas` |
| CA04.1 | `test_ca04_1_caminho_vem_da_linha_de_comando`, `test_ca04_1_analisa_apenas_ssh`, `test_ca04_1_analisa_apenas_web`, `test_ca04_1_analisa_ssh_e_web`, `test_dataset_ca04_1_main_le_o_dataset_pela_linha_de_comando`, `test_dataset_web_ca04_1_le_arquivo_pela_linha_de_comando` |
| CA04.2 | `test_ca04_2_analise_usa_o_arquivo_informado` |
| CA04.3 | `test_ca04_3_arquivo_inexistente_gera_erro_claro` |
| CA04.4 | `test_ca04_4_sem_argumento_mostra_modo_de_uso` |
| CA04.5 | `test_ca04_5_linhas_invalidas_nao_interrompem_a_analise`, `test_ca04_5_relatorio_informa_linhas_ignoradas`, `test_dataset_ca04_5_linhas_de_outros_tipos_nao_quebram` |

## Datasets de teste

### SSH — OpenSSH_2k.log

Os testes de integração usam `data/OpenSSH_2k.log`: 2000 linhas de log real de SSH

O arquivo contém 1999 terminadores `\r\n` e uma última linha sem terminador. Os testes preservam essas quebras ao ler o arquivo. Se o arquivo não existir, os sete testes de integração são pulados (`skipUnless`); com a pasta `data/` presente, devem ser executados.

Fonte: [Loghub — OpenSSH_2k.log](https://github.com/logpai/loghub/blob/master/OpenSSH/OpenSSH_2k.log)

### Web — apache_logs.txt

Os testes de integração usam `data/apache_logs.txt`: 10000 linhas de logs de acessos HTTP no formato Combined, disponibilizadas pela Elastic.

O arquivo é lido diretamente, sem modificar os registros. Se ele não existir, os três testes de integração web são pulados (`skipUnless`); com o arquivo presente em `data/`, devem ser executados.

Fonte: [Elastic — Apache Access Logs](https://github.com/elastic/examples/blob/master/Common%20Data%20Formats/apache_logs/apache_logs).

**Observações sobre modificações no dataset:**
Preservar o arquivo de referência para manter os resultados reproduzíveis. Casos de borda devem usar dados artificiais nos testes ou cópias separadas, sem alterar o log original.

## Como rodar os testes

```
python -m unittest -v test_logsentinel
```

Para rodar o programa: `python main.py --ssh caminho_arquivo --web caminho_arquivo`.

Resultado esperado nesta sprint, com os arquivos SSH e web presentes: 36 testes executados, com 36 erros `NotImplementedError` e nenhum teste pulado. Isso representa a etapa vermelha do TDD; a implementação das funcionalidades fica para a Sprint 3.
