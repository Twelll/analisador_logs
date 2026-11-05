# LogSentinel — Analisador de logs e identificação de atividades suspeitas

Ferramenta de terminal em Python para analisar logs ssh e web (apache)

## Etapa atual: Sprint 2

Esta entrega contém quatro histórias de usuário, seus critérios de aceitação e 36 testes automatizados. As funções ainda lançam `NotImplementedError`: os testes especificam o comportamento que será implementado na Sprint 3.

- [Proposta e pesquisa da Sprint 1](docs/sprint-1-proposta.md)
- [Histórias, critérios e relação com os testes da Sprint 2](docs/sprint-2-historias.md)

## Estrutura

```text
main.py                      # inicializador auxiliar
logsentinel.py               # contratos das funções, ainda sem implementação
test_logsentinel.py          # testes das quatro histórias
data/
  OpenSSH_2k.log             # referência dos sete testes de integração SSH
  apache_logs.txt            # acessos Apache publicados pela Elastic
docs/
  sprint-1-proposta.md
  sprint-2-historias.md
```

## Executar os testes

Na pasta do projeto, com Python 3:

```text
python -m unittest -v test_logsentinel
```

Com os logs SSH e web presentes, o resultado esperado nesta etapa é de 36 erros `NotImplementedError`, sem testes pulados. São sete testes de integração SSH e três web; se um arquivo de referência faltar, os testes correspondentes são pulados. Não há dependências externas para executar os testes.

## Uso previsto para a Sprint 3

Os comandos abaixo descrevem o contrato; ainda não funcionam na Sprint 2:

```text
python main.py --ssh data/OpenSSH_2k.log
python main.py --web data/apache_logs.txt
python main.py --ssh data/OpenSSH_2k.log --web data/apache_logs.txt
```

É necessário informar ao menos um caminho, com `--ssh` ou `--web`. Não há arquivo JSON de configuração na US04. `--ano` informa o ano dos registros SSH e tem padrão 2026. O ponto de entrada de `logsentinel.py` também permite executar `python logsentinel.py` com os mesmos argumentos.

## Dados de referência

O dataset web é `data/apache_logs.txt`, publicado pela [Elastic](https://github.com/elastic/examples/tree/master/Common%20Data%20Formats/apache_logs): 10000 registros em Combined e 213 respostas 404. A contagem independente aponta um IP que atinge o limite padrão de 10 respostas 404 em 60 segundos: `144.76.95.39`. O arquivo original contém uma linha com o campo do navegador truncado; seus campos de acesso estão completos. A conferência dos dados não substitui os testes da implementação, que fica para a Sprint 3.

O log SSH é `data/OpenSSH_2k.log`. As contagens e os resultados esperados de ambos os arquivos estão no [documento da Sprint 2](docs/sprint-2-historias.md#datasets-de-teste).


## Próximas etapas

A Sprint 3 trata da arquitetura e da implementação das histórias com os testes passando. A Sprint 4 trata da refatoração e dos padrões de projeto. O empacotamento final deve seguir o enunciado: documentação em PDF e ZIP com código-fonte e testes em dois arquivos `.py`.

## 📄 Licença
Você pode usar, modificar e distribuir este projeto. [MIT License](./LICENSE)

## Desenvolvedores

| [<img loading="lazy" src="https://avatars.githubusercontent.com/u/162636181?v=4" width=115><br><sub>Thiago Wesley</sub>](https://github.com/Twelll) |  [<img loading="lazy" src="https://avatars.githubusercontent.com/u/188865867?v=4" width=115><br><sub>Felipe Rochoel</sub>](https://github.com/rochoel-felipe) |  [<img loading="lazy" src="https://avatars.githubusercontent.com/u/188619435?v=4" width=115><br><sub>Vinicius Gabriel</sub>](https://github.com/Vinegabriel) |
:---: | :---: | :---: |
