"""Testes automatizados do LogSentinel (Sprint 2).

Cada teste verifica um critério de aceitação de docs/sprint-2-historias.md.
O ID do critério (ex.: CA01.2) aparece no nome e na docstring do teste.

Nesta sprint os testes devem FALHAR: as funções ainda não foram
implementadas. Eles servem como especificação para a Sprint 3.

Executar: python -m unittest -v test_logsentinel
"""
import contextlib
import io
import os
import tempfile
import unittest
from datetime import datetime, timedelta

import logsentinel as ls

BASE = datetime(2026, 10, 27, 20, 15, 0)

CFG = {
    "ssh_falhas_limite": 5,
    "ssh_janela_segundos": 60,
    "web_404_limite": 10,
    "web_404_janela_segundos": 60,
}


def evento_ssh(ip, segundos, tipo="ssh_falha"):
    return {
        "tipo": tipo,
        "ip": ip,
        "usuario": "root",
        "horario": BASE + timedelta(seconds=segundos),
    }


def evento_web(ip, segundos, status=404, caminho="/admin"):
    return {
        "tipo": "web",
        "ip": ip,
        "horario": BASE + timedelta(seconds=segundos),
        "metodo": "GET",
        "caminho": caminho,
        "status": status,
    }


def linha_ssh(segundo, ip="192.0.2.10"):
    return (
        f"Oct 27 20:16:{segundo:02d} ubuntu sshd-session[2853967]: "
        f"Failed password for user from {ip} port 19405 ssh2"
    )


class TestUS01FalhasSSH(unittest.TestCase):
    """US01 - Detectar falhas repetidas de autenticação SSH."""

    def test_ca01_1_extrai_ip_de_falha_ssh(self):
        """CA01.1: o IP e o horário são extraídos de uma linha 'Failed password'."""
        ev = ls.parse_ssh_line(linha_ssh(26), year=2026)
        self.assertEqual(ev["tipo"], "ssh_falha")
        self.assertEqual(ev["ip"], "192.0.2.10")
        self.assertEqual(ev["horario"], datetime(2026, 10, 27, 20, 16, 26))

    def test_ca01_1_extrai_ip_de_usuario_invalido(self):
        """CA01.1: também funciona para 'Failed password for invalid user'."""
        linha = (
            "Oct 27 20:16:27 ubuntu sshd[2853968]: "
            "Failed password for invalid user admin from 198.51.100.7 port 4022 ssh2"
        )
        ev = ls.parse_ssh_line(linha, year=2026)
        self.assertEqual(ev["ip"], "198.51.100.7")

    def test_ca01_2_alerta_ao_atingir_limite_na_janela(self):
        """CA01.2: 5 falhas em 20 s (limite 5, janela 60 s) geram 1 alerta."""
        eventos = [evento_ssh("192.0.2.10", i * 5) for i in range(5)]
        alertas = ls.detect_ssh_bruteforce(eventos, CFG)
        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["ip"], "192.0.2.10")
        self.assertEqual(alertas[0]["ocorrencias"], 5)

    def test_ca01_3_sem_alerta_abaixo_do_limite(self):
        """CA01.3: 4 falhas (limite 5) não geram alerta."""
        eventos = [evento_ssh("192.0.2.10", i * 5) for i in range(4)]
        self.assertEqual(ls.detect_ssh_bruteforce(eventos, CFG), [])

    def test_ca01_3_ips_diferentes_nao_sao_somados(self):
        """CA01.3: 3 falhas de cada um de 2 IPs não somam 6 para nenhum deles."""
        eventos = [evento_ssh("192.0.2.10", i) for i in range(3)]
        eventos += [evento_ssh("198.51.100.7", i) for i in range(3)]
        self.assertEqual(ls.detect_ssh_bruteforce(eventos, CFG), [])

    def test_ca01_4_falhas_fora_da_janela_nao_sao_somadas(self):
        """CA01.4: 5 falhas espaçadas de 120 s nunca têm 5 dentro de 60 s."""
        eventos = [evento_ssh("192.0.2.10", i * 120) for i in range(5)]
        self.assertEqual(ls.detect_ssh_bruteforce(eventos, CFG), [])

    def test_ca01_5_login_com_sucesso_nao_conta_como_falha(self):
        """CA01.5: 10 logins bem-sucedidos não geram alerta."""
        eventos = [
            evento_ssh("192.0.2.10", i * 5, tipo="ssh_sucesso") for i in range(10)
        ]
        self.assertEqual(ls.detect_ssh_bruteforce(eventos, CFG), [])

    def test_ca01_5_parser_identifica_login_com_sucesso(self):
        """CA01.5: linha 'Accepted password' vira evento 'ssh_sucesso'."""
        linha = (
            "Oct 27 20:17:00 ubuntu sshd[2853970]: "
            "Accepted password for felipe from 192.0.2.20 port 5000 ssh2"
        )
        ev = ls.parse_ssh_line(linha, year=2026)
        self.assertEqual(ev["tipo"], "ssh_sucesso")


class TestUS02Web404(unittest.TestCase):
    """US02 - Detectar excesso de respostas 404 no log web."""

    LINHA = (
        '203.0.113.5 - - [27/Oct/2026:20:16:02 -0300] '
        '"GET /admin HTTP/1.1" 404 512 "-" "curl/8.0"'
    )

    def test_ca02_1_extrai_campos_dos_formatos_de_acesso(self):
        """CA02.1: Common e Combined fornecem IP, horário, caminho e status."""
        linha_common = (
            '203.0.113.5 - - [27/Oct/2026:20:16:02 -0300] '
            '"GET /admin HTTP/1.1" 404 512'
        )
        for linha in (linha_common, self.LINHA):
            ev = ls.parse_web_line(linha)
            self.assertEqual(ev["ip"], "203.0.113.5")
            self.assertEqual(ev["caminho"], "/admin")
            self.assertEqual(ev["status"], 404)
            self.assertEqual(ev["horario"].strftime("%d/%m %H:%M:%S"), "27/10 20:16:02")

    def test_ca02_2_alerta_ao_atingir_limite_de_404(self):
        """CA02.2: 10 respostas 404 em 27 s (limite 10, janela 60 s) geram 1 alerta."""
        eventos = [evento_web("203.0.113.5", i * 3) for i in range(10)]
        alertas = ls.detect_web_404(eventos, CFG)
        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["ip"], "203.0.113.5")
        self.assertEqual(alertas[0]["ocorrencias"], 10)

    def test_ca02_3_outros_status_nao_contam(self):
        """CA02.3: respostas 200 e 500 não entram na contagem de 404."""
        eventos = [evento_web("203.0.113.5", i, status=200) for i in range(10)]
        self.assertEqual(ls.detect_web_404(eventos, CFG), [])
        misto = [evento_web("203.0.113.5", i, status=404) for i in range(5)]
        misto += [evento_web("203.0.113.5", 10 + i, status=500) for i in range(5)]
        self.assertEqual(ls.detect_web_404(misto, CFG), [])

    def test_ca02_4_alerta_traz_caminhos_como_evidencia(self):
        """CA02.4: os caminhos acessados aparecem nas evidências do alerta."""
        caminhos = ["/admin", "/login", "/.env", "/wp-admin", "/backup"] * 2
        eventos = [
            evento_web("203.0.113.5", i, caminho=c) for i, c in enumerate(caminhos)
        ]
        alerta = ls.detect_web_404(eventos, CFG)[0]
        texto = " ".join(alerta["evidencias"])
        self.assertIn("/admin", texto)
        self.assertIn("/.env", texto)


class TestUS03Relatorio(unittest.TestCase):
    """US03 - Relatório com IP, período, ocorrências, motivo e nível."""

    def _alerta(self, ip, nivel, ocorrencias=12):
        return {
            "ip": ip,
            "fonte": "ssh",
            "inicio": BASE,
            "fim": BASE + timedelta(seconds=60),
            "ocorrencias": ocorrencias,
            "motivo": "Falhas repetidas de autenticação SSH",
            "nivel": nivel,
            "evidencias": [],
        }

    def test_ca03_1_relatorio_mostra_campos_do_alerta(self):
        """CA03.1: IP, período, ocorrências, motivo e nível aparecem no relatório."""
        resultado = {"alertas": [self._alerta("192.0.2.10", 8)], "linhas_ignoradas": 0}
        texto = ls.format_report(resultado)
        for esperado in ("192.0.2.10", "20:15", "20:16", "12", "Falhas repetidas", "8/10"):
            self.assertIn(esperado, texto)

    def test_ca03_1_relatorio_ponta_a_ponta(self):
        """CA03.1: das linhas de log até o relatório (fluxo completo)."""
        linhas = [linha_ssh(s) for s in range(12)]
        resultado = ls.analyze_lines(linhas, year=2026)
        texto = ls.format_report(resultado)
        self.assertIn("192.0.2.10", texto)
        self.assertIn("12", texto)

    def test_ca03_2_nivel_entre_1_e_10_e_nao_decrescente(self):
        """CA03.2: o nível é inteiro de 1 a 10 e não cai quando as ocorrências sobem."""
        limite = 5
        anterior = 0
        for ocorrencias in range(limite, limite * 10):
            nivel = ls.calcular_nivel(ocorrencias, limite)
            self.assertIsInstance(nivel, int)
            self.assertGreaterEqual(nivel, 1)
            self.assertLessEqual(nivel, 10)
            self.assertGreaterEqual(nivel, anterior)
            anterior = nivel

    def test_ca03_3_alertas_ordenados_do_maior_para_o_menor_nivel(self):
        """CA03.3: o alerta de nível 9 aparece antes do de nível 3."""
        resultado = {
            "alertas": [
                self._alerta("198.51.100.7", 3),
                self._alerta("192.0.2.10", 9),
            ],
            "linhas_ignoradas": 0,
        }
        texto = ls.format_report(resultado)
        self.assertLess(texto.index("192.0.2.10"), texto.index("198.51.100.7"))

    def test_ca03_4_relatorio_sem_alertas(self):
        """CA03.4: sem alertas, o relatório diz que nada suspeito foi encontrado."""
        texto = ls.format_report({"alertas": [], "linhas_ignoradas": 0})
        self.assertIn("Nenhuma atividade suspeita", texto)


class TestUS04ArquivoDeEntrada(unittest.TestCase):
    """US04 - Informar o arquivo de log na linha de comando."""

    def _executar(self, argv):
        saida, erro = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
            codigo = ls.main(argv)
        return codigo, saida.getvalue(), erro.getvalue()

    def _criar_log(self, pasta, linhas, nome="auth.log"):
        caminho = os.path.join(pasta, nome)
        with open(caminho, "w", encoding="utf-8") as f:
            f.write("\n".join(linhas) + "\n")
        return caminho

    def test_ca04_1_caminho_vem_da_linha_de_comando(self):
        """CA04.1: --ssh recebe o caminho, imprime o relatório e retorna 0."""
        with tempfile.TemporaryDirectory() as pasta:
            caminho = self._criar_log(pasta, [linha_ssh(s) for s in range(5)])
            codigo, saida, _ = self._executar(["--ssh", caminho])
        self.assertEqual(codigo, 0)
        self.assertIn("192.0.2.10", saida)

    def test_ca04_2_analise_usa_o_arquivo_informado(self):
        """CA04.2: arquivos diferentes produzem relatórios diferentes."""
        with tempfile.TemporaryDirectory() as pasta:
            a = self._criar_log(pasta, [linha_ssh(s) for s in range(5)], "a.log")
            b = self._criar_log(
                pasta, [linha_ssh(s, ip="198.51.100.7") for s in range(5)], "b.log"
            )
            codigo_a, saida_a, erro_a = self._executar(["--ssh", a])
            codigo_b, saida_b, erro_b = self._executar(["--ssh", b])
        self.assertEqual((codigo_a, codigo_b), (0, 0))
        self.assertEqual((erro_a, erro_b), ("", ""))
        self.assertIn("192.0.2.10", saida_a)
        self.assertNotIn("198.51.100.7", saida_a)
        self.assertIn("198.51.100.7", saida_b)
        self.assertNotIn("192.0.2.10", saida_b)

    def test_ca04_3_arquivo_inexistente_gera_erro_claro(self):
        """CA04.3: arquivo que não existe -> código diferente de 0 e mensagem no stderr."""
        codigo, _, erro = self._executar(["--ssh", "nao_existe.log"])
        self.assertNotEqual(codigo, 0)
        self.assertIn("nao_existe.log", erro)
        self.assertNotIn("Traceback", erro)

    def test_ca04_4_sem_argumento_mostra_modo_de_uso(self):
        """CA04.4: sem informar o arquivo, o programa encerra com código diferente de 0."""
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                ls.main([])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_ca04_5_linhas_invalidas_nao_interrompem_a_analise(self):
        """CA04.5: lixo no meio do log é ignorado e os alertas válidos saem."""
        linhas = [linha_ssh(s) for s in range(5)]
        linhas.insert(2, "isto não é uma linha de log")
        linhas.append("###")
        resultado = ls.analyze_lines(linhas, year=2026)
        self.assertEqual(len(resultado["alertas"]), 1)

    def test_ca04_5_relatorio_informa_linhas_ignoradas(self):
        """CA04.5: o resultado conta as linhas ignoradas e o relatório as cita."""
        linhas = [linha_ssh(s) for s in range(5)] + ["lixo 1", "lixo 2"]
        resultado = ls.analyze_lines(linhas, year=2026)
        self.assertEqual(resultado["linhas_ignoradas"], 2)
        self.assertIn("2", ls.format_report(resultado))

    def test_ca04_1_analisa_apenas_ssh(self):
        """CA04.1: permite analisar apenas SSH, sem informar um arquivo web."""
        with tempfile.TemporaryDirectory() as pasta:
            caminho = self._criar_log(
                pasta,
                [linha_ssh(s) for s in range(5)],
                "auth.log"
            )

            codigo, saida, erro = self._executar(["--ssh", caminho])

            self.assertEqual(codigo, 0)
            self.assertIn("192.0.2.10", saida)
            self.assertEqual(erro, "")

    def test_ca04_1_analisa_apenas_web(self):
        """CA04.1: permite analisar apenas web, sem informar um arquivo SSH."""
        with tempfile.TemporaryDirectory() as pasta:
            linha_web = (
                '203.0.113.5 - - [27/Oct/2026:20:16:02 -0300] '
                '"GET /admin HTTP/1.1" 404 512 "-" "curl/8.0"'
            )
            caminho = self._criar_log(
                pasta,
                [linha_web] * 10,
                "access.log"
            )

            codigo, saida, erro = self._executar(["--web", caminho])

            self.assertEqual(codigo, 0)
            self.assertIn("203.0.113.5", saida)
            self.assertEqual(erro, "")

    def test_ca04_1_analisa_ssh_e_web(self):
        """CA04.1: permite analisar SSH e web simultaneamente."""
        with tempfile.TemporaryDirectory() as pasta:
            ssh = self._criar_log(
                pasta,
                [linha_ssh(s) for s in range(5)],
                "auth.log"
            )

            linha_web = (
                '203.0.113.5 - - [27/Oct/2026:20:16:02 -0300] '
                '"GET /admin HTTP/1.1" 404 512 "-" "curl/8.0"'
            )
            web = self._criar_log(
                pasta,
                [linha_web] * 10,
                "access.log"
            )

            codigo, saida, erro = self._executar(
                ["--ssh", ssh, "--web", web]
            )

            self.assertEqual(codigo, 0)
            self.assertIn("192.0.2.10", saida)
            self.assertIn("203.0.113.5", saida)
            self.assertEqual(erro, "")


ARQUIVO_TESTE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "OpenSSH_2k.log"
)

# Resultados esperados para o arquivo de referência.
# Se os registros forem modificados, estes valores devem ser revisados.
IPS_LIMITE_5 = {
    "103.99.0.122", "112.95.230.3", "119.4.203.64", "123.235.32.19",
    "183.62.140.253", "185.190.58.151", "187.141.143.180", "5.188.10.180",
    "60.2.12.12",
}

IPS_LIMITE_10 = {
    "103.99.0.122", "112.95.230.3", "183.62.140.253", "187.141.143.180",
    "5.188.10.180",
}


@unittest.skipUnless(
    os.path.exists(ARQUIVO_TESTE),
    "Arquivo de log para testes de integração não encontrado",
)
class TestIntegracaoLogs(unittest.TestCase):
    """Testes de integração utilizando registros reais de SSH."""

    @classmethod
    def setUpClass(cls):
        with open(
            ARQUIVO_TESTE,
            encoding="utf-8",
            errors="replace",
            newline=""
        ) as f:
            cls.linhas = f.readlines()

    def test_dataset_ca01_2_alertas_com_limite_padrao(self):
        """CA01.2: com limite 5 e janela de 60 s, exatamente 9 IPs geram alerta."""
        resultado = ls.analyze_lines(self.linhas, year=2026)
        ips = {a["ip"] for a in resultado["alertas"]}
        self.assertEqual(ips, IPS_LIMITE_5)

    def test_dataset_ca01_2_ocorrencias_respeitam_o_limite(self):
        """CA01.2: todo alerta possui pelo menos 5 ocorrências."""
        resultado = ls.analyze_lines(self.linhas, year=2026)
        self.assertTrue(resultado["alertas"])
        for alerta in resultado["alertas"]:
            self.assertGreaterEqual(alerta["ocorrencias"], 5)

    def test_dataset_ca03_3_ip_mais_agressivo_vem_primeiro(self):
        """CA03.3: o IP com maior atividade suspeita aparece primeiro."""
        resultado = ls.analyze_lines(self.linhas, year=2026)
        alertas = resultado["alertas"]

        self.assertTrue(alertas)
        self.assertEqual(alertas[0]["ip"], "183.62.140.253")

        niveis = [a["nivel"] for a in alertas]
        self.assertEqual(niveis, sorted(niveis, reverse=True))

    def test_dataset_ca03_1_relatorio_cita_o_ip_mais_agressivo(self):
        """CA03.1: o relatório apresenta o IP suspeito e seu nível."""
        resultado = ls.analyze_lines(self.linhas, year=2026)
        texto = ls.format_report(resultado)

        self.assertIn("183.62.140.253", texto)
        self.assertIn("/10", texto)

    def test_dataset_ca01_2_limite_maior_reduz_os_alertas(self):
        """CA01.2: aumentar o limite para 10 reduz os alertas para 5 IPs."""
        config = dict(ls.DEFAULT_CONFIG, ssh_falhas_limite=10)
        resultado = ls.analyze_lines(self.linhas, config=config, year=2026)

        ips = {a["ip"] for a in resultado["alertas"]}
        self.assertEqual(ips, IPS_LIMITE_10)

    def test_dataset_ca04_5_linhas_de_outros_tipos_nao_quebram(self):
        """CA04.5: registros não reconhecidos são ignorados sem interromper a análise."""
        resultado = ls.analyze_lines(self.linhas, year=2026)

        self.assertGreater(resultado["linhas_ignoradas"], 0)
        self.assertLess(resultado["linhas_ignoradas"], len(self.linhas))

    def test_dataset_ca04_1_main_le_o_dataset_pela_linha_de_comando(self):
        """CA04.1: o programa analisa o arquivo informado e imprime o relatório."""
        saida = io.StringIO()

        with contextlib.redirect_stdout(saida):
            codigo = ls.main(["--ssh", ARQUIVO_TESTE])

        self.assertEqual(codigo, 0)
        self.assertIn("183.62.140.253", saida.getvalue())


ARQUIVO_WEB_TESTE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "apache_logs.txt"
)


@unittest.skipUnless(
    os.path.exists(ARQUIVO_WEB_TESTE),
    "Arquivo de acessos web para testes de integração não encontrado",
)
class TestIntegracaoWeb(unittest.TestCase):
    """Testes com os registros de acesso Apache publicados pela Elastic."""

    @classmethod
    def setUpClass(cls):
        with open(ARQUIVO_WEB_TESTE, encoding="utf-8", newline="") as f:
            cls.linhas = f.readlines()

    def test_dataset_web_ca02_1_extrai_campos_do_acesso(self):
        """CA02.1: extrai os campos de uma resposta 404 do arquivo original."""
        evento = ls.parse_web_line(self.linhas[62])
        self.assertEqual(evento["tipo"], "web")
        self.assertEqual(evento["ip"], "66.249.73.185")
        self.assertEqual(evento["metodo"], "GET")
        self.assertEqual(
            evento["caminho"],
            "/doc/index.html?org/elasticsearch/action/search/SearchResponse.html",
        )
        self.assertEqual(evento["status"], 404)
        self.assertEqual(
            evento["horario"].strftime("%Y-%m-%d %H:%M:%S"),
            "2015-05-17 10:05:22",
        )

    def test_dataset_web_ca02_2_alerta_com_limite_padrao(self):
        """CA02.2: somente 144.76.95.39 atinge 10 respostas 404 em 60 s."""
        resultado = ls.analyze_lines(self.linhas)
        alertas = resultado["alertas"]
        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["ip"], "144.76.95.39")
        self.assertEqual(alertas[0]["fonte"], "web")
        self.assertGreaterEqual(alertas[0]["ocorrencias"], 10)

    def test_dataset_web_ca04_1_le_arquivo_pela_linha_de_comando(self):
        """CA04.1: --web lê o arquivo de referência e imprime o relatório."""
        saida, erro = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
            codigo = ls.main(["--web", ARQUIVO_WEB_TESTE])
        self.assertEqual(codigo, 0)
        self.assertIn("144.76.95.39", saida.getvalue())
        self.assertEqual(erro.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
