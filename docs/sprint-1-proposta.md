# Sprint 1 — Definição da proposta

**Projeto:** LogSentinel — Analisador de logs e identificação de atividades suspeitas

## 1. Integrantes

1. Felipe Rochoel Costa
2. Thiago Wesley Pasquim De Melo
3. Vinicius Gabriel Giordani Barbosa

## 2. Descrição do sistema

O sistema auxiliará na investigação de atividades suspeitas registradas em acessos SSH e web.
Seu público-alvo será composto por administradores de pequenos servidores e desenvolvedores.
A entrada será um arquivo de log, contendo registros como:
Oct 27 20:16:26 ubuntu sshd-session[2853967]: Failed password for user from 192.0.2.10 port 19405 ssh2
A saída reunirá os eventos suspeitos e sua análise, conforme o exemplo:
IP analisado: 192.0.2.10
Período: 27/10, das 20:15 às 20:16
Ocorrências: 12 falhas de autenticação SSH em 1 minuto
Motivo: Falhas repetidas de autenticação no intervalo analisado.
Nível de suspeita: 8/10, conforme os critérios de detecção definidos.

## 3. Pesquisa e justificativa da relevância

A pesquisa usou duas fontes: as estatísticas de incidentes do CERT.br e o Logging Cheat Sheet da OWASP. Uma justifica o problema, a outra justifica o uso de logs como entrada.

O CERT.br reúne notificações de incidentes enviadas por administradores de redes, equipes de resposta e usuários. Sua categoria Scan inclui varreduras e tentativas de força bruta de senhas, e a categoria Web inclui ataques a servidores web. Ou seja, os casos que o projeto trata acontecem em serviços expostos na Internet. As notificações são voluntárias, então não representam todos os incidentes do Brasil nem o risco de um servidor específico.

A OWASP trata os logs como fonte para identificar e investigar incidentes. Recomenda registrar sucessos e falhas de autenticação, guardar contexto (momento, origem, ação e resultado) e relacionar eventos de fontes diferentes.

Com base nisso, o LogSentinel propõe organizar os registros e destacar o que merece investigação, reduzindo o trabalho de procurar e cruzar eventos à mão em arquivos separados. Esse ganho é uma hipótese da proposta, ainda não medido. Falhas de autenticação, respostas 404 e alto volume de acessos serão tratados como indícios que dependem de contexto. O relatório mostra a regra acionada e as evidências, e o administrador decide o que fazer com cada alerta.

## 4. Referências

[1] CENTRO DE ESTUDOS, RESPOSTA E TRATAMENTO DE INCIDENTES DE SEGURANÇA NO BRASIL (CERT.br). **Estatísticas de incidentes notificados ao CERT.br**. NIC.br, [s.d.]. Disponível em: <https://stats.cert.br/incidentes/>. Acesso em: 27 out. 2026. Seções consultadas: apresentação e descrição das categorias de incidentes reportados.

[2] OWASP FOUNDATION. **Logging Cheat Sheet**. OWASP Cheat Sheet Series, [s.d.]. Disponível em: <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>. Acesso em: 27 out. 2026. Seções consultadas: *Purpose*, *Which events to log*, *Event attributes* e *Monitoring of events*.