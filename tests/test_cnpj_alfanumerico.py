#!/usr/bin/env python
# *-* encoding: utf8 *-*

"""
Testes de suporte a CNPJ alfanumérico (IN RFB nº 2.229/2024, vigente jul/2026).

O CNPJ passa a admitir letras maiúsculas A-Z nas 12 primeiras posições; os 2
dígitos verificadores continuam numéricos. CNPJs 100% numéricos e CPFs
continuam válidos e devem produzir exatamente o mesmo resultado de antes
(retrocompatibilidade).

Obs.: estes testes NÃO validam contra XSD, pois os schemas oficiais da SEFAZ
empacotados ainda usam pattern numérico [0-9]{14}/[0-9]{44}. A atualização do
pattern depende do pacote XSD oficial atualizado (ver xsd_pending).
"""

import datetime
import unittest
from decimal import Decimal

from pynfe.entidades.cliente import Cliente
from pynfe.entidades.emitente import Emitente
from pynfe.entidades.fonte_dados import _fonte_dados
from pynfe.entidades.notafiscal import NotaFiscal
from pynfe.processamento.serializacao import SerializacaoXML
from pynfe.utils import normalizar_documento, so_numeros


# CNPJ alfanumérico de exemplo (12 posições base alfanuméricas + 2 DV numéricos)
CNPJ_ALFA = "12ABC34501DE35"
CNPJ_NUM = "99999999000199"
CPF_NUM = "12345678900"


class NormalizarDocumentoTestCase(unittest.TestCase):
    def test_retrocompat_cnpj_numerico(self):
        # Para entrada 100% numérica o resultado é idêntico ao so_numeros de hoje.
        self.assertEqual(normalizar_documento(CNPJ_NUM), so_numeros(CNPJ_NUM))
        self.assertEqual(normalizar_documento(CNPJ_NUM), CNPJ_NUM)

    def test_retrocompat_cpf_numerico(self):
        self.assertEqual(normalizar_documento(CPF_NUM), so_numeros(CPF_NUM))
        self.assertEqual(normalizar_documento(CPF_NUM), CPF_NUM)

    def test_remove_mascara_cnpj_alfanumerico(self):
        self.assertEqual(normalizar_documento("12.ABC.345/01DE-35"), CNPJ_ALFA)

    def test_uppercase(self):
        self.assertEqual(normalizar_documento("12abc34501de35"), CNPJ_ALFA)

    def test_preserva_14_posicoes(self):
        self.assertEqual(len(normalizar_documento(CNPJ_ALFA)), 14)

    def test_none_e_vazio(self):
        self.assertEqual(normalizar_documento(None), "")
        self.assertEqual(normalizar_documento(""), "")

    def test_cnpj_alfanumerico_nao_e_confundido_com_cpf(self):
        # so_numeros descarta as letras (deixaria menos de 14 dígitos e poderia
        # ser confundido com CPF); normalizar_documento mantém 14 chars ->
        # corretamente CNPJ.
        self.assertNotEqual(len(so_numeros(CNPJ_ALFA)), 14)
        self.assertEqual(len(normalizar_documento(CNPJ_ALFA)), 14)


class DVCodigoNumericoTestCase(unittest.TestCase):
    def _nova_nota(self, cnpj):
        emitente = Emitente(razao_social="EMPRESA TESTE", nome_fantasia="TESTE", cnpj=cnpj)
        utc = datetime.timezone.utc
        return NotaFiscal(
            emitente=emitente,
            uf="PR",
            modelo=55,
            serie="1",
            numero_nf="111",
            data_emissao=datetime.datetime(2026, 7, 7, 12, 0, 0, tzinfo=utc),
            forma_emissao="1",
        )

    def test_dv_numerico_retrocompat(self):
        # DV por ord(c)-48 deve ser idêntico ao antigo int(c) para chave numérica.
        nota = self._nova_nota(CNPJ_NUM)
        key = "43" + "9" * 41  # 43 posições numéricas
        # implementação de referência (antiga, com int())
        weights = [2, 3, 4, 5, 6, 7, 8, 9]
        nums = [int(k) for k in key]
        nums.reverse()
        s = sum(n * weights[i % len(weights)] for i, n in enumerate(nums))
        r = s % 11
        esperado = "0" if r in (0, 1) else str(11 - r)
        self.assertEqual(nota._dv_codigo_numerico(key), esperado)

    def test_dv_alfanumerico_nao_quebra(self):
        # Chave com letras (CNPJ alfanumérico embutido) deve calcular sem erro
        # e retornar um único dígito verificador.
        nota = self._nova_nota(CNPJ_ALFA)
        # cUF(2)+AAMM(4)+CNPJ(14)+mod(2)+serie(3)+nNF(9)+tpEmis(1)+cNF(8) = 43
        key = "412607" + CNPJ_ALFA + "55" + "001" + "000000111" + "1" + "12345678"
        self.assertEqual(len(key), 43)
        dv = nota._dv_codigo_numerico(key)
        self.assertTrue(dv.isdigit())
        self.assertEqual(len(dv), 1)


class IdentificadorUnicoTestCase(unittest.TestCase):
    def _nova_nota(self, cnpj):
        emitente = Emitente(razao_social="EMPRESA TESTE", nome_fantasia="TESTE", cnpj=cnpj)
        utc = datetime.timezone.utc
        nota = NotaFiscal(
            emitente=emitente,
            uf="PR",
            modelo=55,
            serie="1",
            numero_nf="111",
            data_emissao=datetime.datetime(2026, 7, 7, 12, 0, 0, tzinfo=utc),
            forma_emissao="1",
        )
        nota.codigo_numerico_aleatorio = "12345678"
        return nota

    def test_chave_embute_cnpj_alfanumerico(self):
        chave = self._nova_nota(CNPJ_ALFA).identificador_unico
        # NFe + 44 caracteres
        self.assertTrue(chave.startswith("NFe"))
        corpo = chave[3:]
        self.assertEqual(len(corpo), 44)
        # posições 7-20 (0-indexed 6:20) embutem o CNPJ do emitente
        self.assertEqual(corpo[6:20], CNPJ_ALFA)
        # DV final numérico
        self.assertTrue(corpo[-1].isdigit())

    def test_chave_cnpj_numerico_retrocompat(self):
        chave = self._nova_nota(CNPJ_NUM).identificador_unico
        corpo = chave[3:]
        self.assertEqual(len(corpo), 44)
        self.assertEqual(corpo[6:20], CNPJ_NUM)
        # chave numérica permanece 100% numérica
        self.assertTrue(corpo.isdigit())


class SerializacaoEmitenteDestTestCase(unittest.TestCase):
    def _serializador(self):
        return SerializacaoXML(fonte_dados=_fonte_dados, homologacao=True)

    def _emitente(self, cnpj):
        return Emitente(
            razao_social="EMPRESA TESTE",
            nome_fantasia="TESTE",
            cnpj=cnpj,
            codigo_de_regime_tributario="3",
            inscricao_estadual="9999999999",
            inscricao_municipal="12345",
            cnae_fiscal="9999999",
            endereco_logradouro="Rua da Paz",
            endereco_numero="666",
            endereco_bairro="Sossego",
            endereco_municipio="Paranavai",
            endereco_uf="PR",
            endereco_cep="87704000",
            endereco_pais="1058",
        )

    def test_emitente_cnpj_alfanumerico(self):
        raiz = self._serializador()._serializar_emitente(
            self._emitente(CNPJ_ALFA), retorna_string=False
        )
        cnpj = raiz.find("CNPJ")
        self.assertIsNotNone(cnpj)
        self.assertEqual(cnpj.text, CNPJ_ALFA)
        # não deve ter gerado tag CPF
        self.assertIsNone(raiz.find("CPF"))
        # CEP continua somente numérico
        self.assertEqual(raiz.find("enderEmit/CEP").text, "87704000")

    def test_emitente_cnpj_numerico_retrocompat(self):
        raiz = self._serializador()._serializar_emitente(
            self._emitente(CNPJ_NUM), retorna_string=False
        )
        self.assertEqual(raiz.find("CNPJ").text, CNPJ_NUM)

    def test_destinatario_cnpj_alfanumerico(self):
        cliente = Cliente(
            indicador_ie=9,
            tipo_documento="CNPJ",
            numero_documento="12.ABC.345/01DE-35",
        )
        serializador = self._serializador()
        serializador._so_cpf = True
        raiz = serializador._serializar_cliente(cliente, modelo=55, retorna_string=False)
        self.assertEqual(raiz.find("CNPJ").text, CNPJ_ALFA)

    def test_destinatario_cpf_retrocompat(self):
        cliente = Cliente(
            indicador_ie=9,
            tipo_documento="CPF",
            numero_documento=CPF_NUM,
        )
        serializador = self._serializador()
        serializador._so_cpf = True
        raiz = serializador._serializar_cliente(cliente, modelo=55, retorna_string=False)
        self.assertEqual(raiz.find("CPF").text, CPF_NUM)


if __name__ == "__main__":
    unittest.main()
