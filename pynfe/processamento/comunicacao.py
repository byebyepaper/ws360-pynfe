# -*- coding: utf-8 -*-
import datetime
import time
import requests
from pynfe.utils import etree, so_numeros
from pynfe.utils.flags import NAMESPACE_NFE, NAMESPACE_SOAP, NAMESPACE_XSI, NAMESPACE_XSD, NAMESPACE_METODO, VERSAO_PADRAO, CODIGOS_ESTADOS, \
NAMESPACE_SOAP_NFSE, NAMESPACE_BETHA
from pynfe.utils.webservices import NFCE, NFE, NFSE
from .assinatura import AssinaturaA1
from pynfe.entidades.certificado import CertificadoA1

class Comunicacao(object):
    u"""Classe abstrata responsavel por definir os metodos e logica das classes
    de comunicação com os webservices da NF-e."""

    _ambiente = 1   # 1 = Produção, 2 = Homologação
    uf = None
    certificado = None
    certificado_senha = None
    url = None

    def __init__(self, uf, certificado, certificado_senha, homologacao=False):
        self.uf = uf
        self.certificado = certificado
        self.certificado_senha = certificado_senha
        self._ambiente = 2 if homologacao else 1

class ComunicacaoSefaz(Comunicacao):
    u"""Classe de comunicação que segue o padrão definido para as SEFAZ dos Estados."""

    _versao = VERSAO_PADRAO
    _assinatura = AssinaturaA1

    def autorizacao(self, modelo, nota_fiscal, idlote=1, indSinc=1):
        # url do serviço
        url = self._get_url(modelo=modelo, consulta='AUTORIZACAO')
        # Monta XML do corpo da requisição
        raiz = etree.Element('enviNFe', xmlns=NAMESPACE_NFE, versao=VERSAO_PADRAO)
        etree.SubElement(raiz, 'idLote').text = str(idlote) # numero autoincremental gerado pelo sistema
        etree.SubElement(raiz, 'indSinc').text = str(indSinc) # 0 para assincrono, 1 para sincrono
        raiz.append(nota_fiscal)
        # Monta XML para envio da requisição
        xml = self._construir_xml_status_pr(cabecalho=self._cabecalho_soap(metodo='NfeAutorizacao'), metodo='NfeAutorizacao', dados=raiz)
        # Faz request no Servidor da Sefaz
        retorno = self._post(url, xml)
        
        # Em caso de sucesso, retorna xml com nfe e protocolo de autorização.
        # Caso contrário, envia todo o soap de resposta da Sefaz para decisão do usuário.
        if retorno.status_code == 200:
            if indSinc == 1:
                # Procuta status no xml
                ns = {'ns':'http://www.portalfiscal.inf.br/nfe'}    # namespace
                prot = etree.fromstring(retorno.text)
                try:
                    # Protocolo com envio OK
                    infProt = prot[1][0][0][6]                             # root protNFe
                    status = infProt.xpath("ns:infProt/ns:cStat", namespaces=ns)[0].text
                except IndexError:
                    # Protocolo com algum erro no Envio
                    retEnvi = prot[1][0][0]                             # root retEnvi
                    status = retEnvi.xpath("ns:cStat", namespaces=ns)[0].text
                if status == '100':
                    raiz = etree.Element('nfeProc', xmlns=NAMESPACE_NFE, versao=VERSAO_PADRAO)
                    raiz.append(nota_fiscal)
                    raiz.append(infProt)
                    return 0, raiz
            else:
                # Retorna id do protocolo para posterior consulta em caso de sucesso.
                ns = {'ns':'http://www.portalfiscal.inf.br/nfe'}    # namespace
                rec = etree.fromstring(retorno.text)
                rec = rec[1][0][0]
                status = rec.xpath("ns:cStat", namespaces=ns)[0].text
                # Lote Recebido com Sucesso!
                if status == '103':
                    nrec = rec.xpath("ns:infRec/ns:nRec", namespaces=ns)[0].text
                    return 0, nrec, nota_fiscal
        return 1, retorno, nota_fiscal

    def consulta_recibo(self, modelo, numero):
        """
            Este método oferece a consulta do resultado do processamento de um lote de NF-e.
            O aplicativo do Contribuinte deve ser construído de forma a aguardar um tempo mínimo de
            15 segundos entre o envio do Lote de NF-e para processamento e a consulta do resultado
            deste processamento, evitando a obtenção desnecessária do status de erro 105 - "Lote em
            Processamento".
        """
        # url do serviço
        url = self._get_url(modelo=modelo, consulta='RECIBO')
        # Monta XML do corpo da requisição
        raiz = etree.Element('consReciNFe', versao=VERSAO_PADRAO, xmlns=NAMESPACE_NFE)
        etree.SubElement(raiz, 'tpAmb').text = str(self._ambiente)
        etree.SubElement(raiz, 'nRec').text = numero
        # Monta XML para envio da requisição
        xml = self._construir_xml_status_pr(cabecalho=self._cabecalho_soap(metodo='NfeRetAutorizacao'), metodo='NfeRetAutorizacao', dados=raiz)
        
        return self._post(url, xml)

    def consulta_nota(self, modelo, chave):
        """
            Este método oferece a consulta da situação da NF-e/NFC-e na Base de Dados do Portal da Secretaria de Fazenda Estadual.
        """
        # url do serviço
        url = self._get_url(modelo=modelo, consulta='CHAVE')
        # Monta XML do corpo da requisição
        raiz = etree.Element('consSitNFe', versao=VERSAO_PADRAO, xmlns=NAMESPACE_NFE)
        etree.SubElement(raiz, 'tpAmb').text = str(self._ambiente)
        etree.SubElement(raiz, 'xServ').text = 'CONSULTAR'
        etree.SubElement(raiz, 'chNFe').text = chave
        # Monta XML para envio da requisição
        xml = self._construir_xml_status_pr(cabecalho=self._cabecalho_soap(metodo='NfeConsulta2'), metodo='NfeConsulta2', dados=raiz)
        
        return self._post(url, xml)

    def consulta_notas_cnpj(self, cnpj, nsu=0):
        """
            “Serviço de Consulta da Relação de Documentos Destinados” para um determinado CNPJ de destinatário informado na NF-e. 
        """
        # url do serviço
        url = self._get_url(modelo='nfe', consulta='DESTINADAS')
        # Monta XML do corpo da requisição
        raiz = etree.Element('consNFeDest', versao='1.01', xmlns=NAMESPACE_NFE)
        etree.SubElement(raiz, 'tpAmb').text = str(self._ambiente)
        etree.SubElement(raiz, 'xServ').text = 'CONSULTAR NFE DEST'
        etree.SubElement(raiz, 'CNPJ').text = cnpj
        # Indicador de NF-e consultada: 
        # 0=Todas as NF-e; 
        # 1=Somente as NF-e que ainda não tiveram manifestação do destinatário (Desconhecimento da operação, Operação não Realizada ou Confirmação da Operação);
        # 2=Idem anterior, incluindo as NF-e que também não tiveram a Ciência da Operação. 
        etree.SubElement(raiz, 'indNFe').text = '0'
        # Indicador do Emissor da NF-e:
        # 0=Todos os Emitentes / Remetentes;
        # 1=Somente as NF-e emitidas por emissores / remetentes que não tenham o mesmo CNPJ-Base do destinatário (para excluir as notas fiscais de transferência entre filiais). 
        etree.SubElement(raiz, 'indEmi').text = '0'
        # Último NSU recebido pela Empresa. Caso seja informado com zero, ou com um NSU muito antigo, a consulta retornará unicamente as notas fiscais que tenham sido recepcionadas nos últimos 15 dias. 
        etree.SubElement(raiz, 'ultNSU').text = str(nsu)

        # Monta XML para envio da requisição
        xml = self._construir_xml_status_pr(cabecalho=self._cabecalho_soap(metodo='NfeConsultaDest'), metodo='NfeConsultaDest', dados=raiz)

        return self._post(url, xml)

    def consulta_distribuicao(self, cnpj, nsu=0):
        pass

    def cancelar(self, modelo, evento, idlote=1):
        """ Envia um evento de cancelamento de nota fiscal """
        # url do serviço
        url = self._get_url(modelo=modelo, consulta='EVENTOS')
        # Monta XML do corpo da requisição
        raiz = etree.Element('envEvento', versao='1.00', xmlns=NAMESPACE_NFE)
        etree.SubElement(raiz, 'idLote').text = str(idlote) # numero autoincremental gerado pelo sistema
        raiz.append(evento)
        xml = self._construir_xml_status_pr(cabecalho=self._cabecalho_soap(metodo='RecepcaoEvento'), metodo='RecepcaoEvento', dados=raiz)
        return self._post(url, xml)

    def status_servico(self, modelo):
        """ Verifica status do servidor da receita. """
        """ modelo é a string com tipo de serviço que deseja consultar
            Ex: nfe ou nfce 
        """
        url = self._get_url(modelo=modelo, consulta='STATUS')

        # Monta XML do corpo da requisição
        raiz = etree.Element('consStatServ', versao=VERSAO_PADRAO, xmlns=NAMESPACE_NFE)
        etree.SubElement(raiz, 'tpAmb').text = str(self._ambiente)
        etree.SubElement(raiz, 'cUF').text = CODIGOS_ESTADOS[self.uf.upper()]
        etree.SubElement(raiz, 'xServ').text = 'STATUS'
        # Monta XML para envio da requisição
        xml = self._construir_xml_status_pr(cabecalho=self._cabecalho_soap(metodo='NfeStatusServico2'), metodo='NfeStatusServico2', dados=raiz)
        # Chama método que efetua a requisição POST no servidor SOAP
        return self._post(url, xml)

    def consultar_cadastro(self, modelo, ie, cnpj):
        # RS implementa um método diferente na consulta de cadastro
        if self.uf.upper() == 'RS':
            url = NFE['RS']['CADASTRO']
        elif self.uf.upper() == 'SVRS':
            url = NFE['SVRS']['CADASTRO']
        elif self.uf.upper() == 'SVC-RS':
            url = NFE['SVC-RS']['CADASTRO']
        else:
            url = self._get_url(modelo=modelo, consulta='CADASTRO')

        raiz = etree.Element('ConsCad', versao=VERSAO_PADRAO, xmlns=NAMESPACE_NFE)
        info = etree.SubElement(raiz, 'infCons')
        etree.SubElement(info, 'xServ').text = 'CONS-CAD'
        etree.SubElement(info, 'UF').text = self.uf.upper()
        etree.SubElement(info, 'IE').text = ie
        etree.SubElement(info, 'CNPJ').text = cnpj
        #etree.SubElement(info, 'CPF').text = cpf
        # Monta XML para envio da requisição
        xml = self._construir_xml_status_pr(cabecalho=self._cabecalho_soap(metodo='CadConsultaCadastro2'), metodo='CadConsultaCadastro2', dados=raiz)
        # Chama método que efetua a requisição POST no servidor SOAP
        return self._post(url, xml)

    def inutilizar_faixa_numeracao(self, numero_inicial, numero_final, emitente, certificado, senha, ano=None, serie='1', justificativa=''):
        post = '/nfeweb/services/nfestatusservico.asmx'
        metodo = 'NfeInutilizacao2'

        # Valores default
        ano = str(ano or datetime.date.today().year)[-2:]
        uf = CODIGOS_ESTADOS[emitente.endereco_uf]
        cnpj = so_numeros(emitente.cnpj)

        # Identificador da TAG a ser assinada formada com Código da UF + Ano (2 posições) +
        #  CNPJ + modelo + série + nro inicial e nro final precedida do literal “ID”
        id_unico = 'ID%(uf)s%(ano)s%(cnpj)s%(modelo)s%(serie)s%(num_ini)s%(num_fin)s'%{
                'uf': uf,
                'ano': ano,
                'cnpj': cnpj,
                'modelo': '55',
                'serie': serie.zfill(3),
                'num_ini': str(numero_inicial).zfill(9),
                'num_fin': str(numero_final).zfill(9),
                }

        # Monta XML do corpo da requisição # FIXME
        raiz = etree.Element('inutNFe', xmlns="http://www.portalfiscal.inf.br/nfe", versao="1.07")
        inf_inut = etree.SubElement(raiz, 'infInut', Id=id_unico)
        etree.SubElement(inf_inut, 'tpAmb').text = str(self._ambiente)
        etree.SubElement(inf_inut, 'xServ').text = 'INUTILIZAR'
        etree.SubElement(inf_inut, 'cUF').text = uf
        etree.SubElement(inf_inut, 'ano').text = ano
        etree.SubElement(inf_inut, 'CNPJ').text = emitente.cnpj
        etree.SubElement(inf_inut, 'mod').text = '55'
        etree.SubElement(inf_inut, 'serie').text = serie
        etree.SubElement(inf_inut, 'nNFIni').text = str(numero_inicial)
        etree.SubElement(inf_inut, 'nNFFin').text = str(numero_final)
        etree.SubElement(inf_inut, 'xJust').text = justificativa
        #dados = etree.tostring(raiz, encoding='utf-8', xml_declaration=True)

        # Efetua assinatura
        assinatura = self._assinatura(certificado, senha)
        dados = assinatura.assinar_etree(etree.ElementTree(raiz), retorna_xml=True)

        # Monta XML para envio da requisição
        xml = self._construir_xml_soap(
                metodo='nfeRecepcao2', # XXX
                tag_metodo='nfeInutilizacaoNF', # XXX
                cabecalho=self._cabecalho_soap(),
                dados=dados,
                )

        # Chama método que efetua a requisição POST no servidor SOAP
        retorno = self._post(post, xml, self._post_header())

        # Transforma o retorno em etree # TODO
        #retorno = etree.parse(StringIO(retorno))

        return retorno

    def _get_url_AN(self, consulta):
        # producao
        if self._ambiente == 1:
            if consulta == 'DISTRIBUICAO':
                ambiente = 'https://www1.'
            else:
                ambiente = 'https://www.'
        # homologacao
        else:
            ambiente = 'https://hom.'

        self.url = ambiente + NFE['AN'][consulta]
        return self.url


    def _get_url(self, modelo, consulta):
        """ Retorna a url para comunicação com o webservice """
        # estado que implementam webservices proprios
        lista = ['PR','MS','SP','AM','CE','BA','GO','MG','MT','PE','RS']
        if self.uf.upper() in lista:
            if self._ambiente == 1:
                ambiente = 'HTTPS'
            else:
                ambiente = 'HOMOLOGACAO'
            if modelo == 'nfe':
                # nfe Ex: https://nfe.fazenda.pr.gov.br/nfe/NFeStatusServico3
                self.url = NFE[self.uf.upper()][ambiente] + NFE[self.uf.upper()][consulta]
            elif modelo == 'nfce':
                # nfce Ex: https://homologacao.nfce.fazenda.pr.gov.br/nfce/NFeStatusServico3
                self.url = NFCE[self.uf.upper()][ambiente] + NFCE[self.uf.upper()][consulta]
            else:
                # TODO implementar outros tipos de notas como NFS-e
                pass
        # Estados que utilizam outros ambientes
        else:
            self._get_url_uf(modelo, consulta)
        return self.url

    def _get_url_uf(self, modelo, consulta):
        """ Estados que implementam url diferente do padrão nacional"""
        pass

    def _cabecalho_soap(self, metodo):
        u"""Monta o XML do cabeçalho da requisição SOAP"""

        raiz = etree.Element('nfeCabecMsg', xmlns=NAMESPACE_METODO+metodo)
        if metodo == 'RecepcaoEvento':
            etree.SubElement(raiz, 'versaoDados').text = '1.00'
        elif metodo == 'NfeConsultaDest':
            etree.SubElement(raiz, 'versaoDados').text = '1.01'
        else:
            etree.SubElement(raiz, 'versaoDados').text = VERSAO_PADRAO
        etree.SubElement(raiz, 'cUF').text = CODIGOS_ESTADOS[self.uf.upper()]
        return raiz

    def _construir_xml_soap(self, cabecalho, metodo, dados):
        """Mota o XML para o envio via SOAP"""

        raiz = etree.Element('{%s}Envelope'%NAMESPACE_SOAP, nsmap={'soap12': NAMESPACE_SOAP})
        c= etree.SubElement(raiz, '{%s}Header'%NAMESPACE_SOAP)
        c.append(cabecalho)
        body = etree.SubElement(raiz, '{%s}Body'%NAMESPACE_SOAP)
        a = etree.SubElement(body, 'nfeDadosMsg', xmlns=NAMESPACE_METODO+metodo)
        a.append(dados)
        return raiz

    def _construir_xml_status_pr(self, cabecalho, metodo, dados):
        u"""Mota o XML para o envio via SOAP"""

        raiz = etree.Element('{%s}Envelope'%NAMESPACE_SOAP, nsmap={'xsi': NAMESPACE_XSI, 'xsd': NAMESPACE_XSD,'soap': NAMESPACE_SOAP})
        c = etree.SubElement(raiz, '{%s}Header'%NAMESPACE_SOAP)
        c.append(cabecalho)
        body = etree.SubElement(raiz, '{%s}Body'%NAMESPACE_SOAP)
        a = etree.SubElement(body, 'nfeDadosMsg', xmlns=NAMESPACE_METODO+metodo)
        a.append(dados)
        return raiz

    def _post_header(self):
        u"""Retorna um dicionário com os atributos para o cabeçalho da requisição HTTP"""
        return {
            u'content-type': u'application/soap+xml; charset=utf-8;',
            u'Accept': u'application/soap+xml; charset=utf-8;',
            }

    def _post(self, url, xml):
        certificadoA1 = CertificadoA1(self.certificado)
        chave, cert = certificadoA1.separar_arquivo(self.certificado_senha, caminho=True)
        chave_cert = (cert, chave)
        # Abre a conexão HTTPS
        try:
            xml_declaration='<?xml version="1.0" encoding="utf-8"?>'
            xml = etree.tostring(xml, encoding='unicode', pretty_print=False).replace('\n','')
            xml = xml_declaration + xml

            # Faz o request com o servidor
            result = requests.post(url, xml, headers=self._post_header(), cert=chave_cert, verify=False)
            result.encoding='utf-8'
            return result
        except requests.exceptions.ConnectionError as e:
            raise e
        finally:
            certificadoA1.excluir()


class ComunicacaoNfse(Comunicacao):
    """ Classe de comunicação que segue o padrão definido para as SEFAZ dos Municípios. """

    _versao = ''
    _namespace = ''

    def autorizacao(self, autorizador, nota):
        if autorizador.upper() == 'BETHA':
            self._namespace = NAMESPACE_BETHA
            self._versao = '2.02'
        # url do serviço
        url = self._get_url(autorizador) + NFSE[autorizador.upper()]['AUTORIZACAO']
        # gerar
        raiz = etree.Element('GerarNfse')
        # cabecalho
        raiz.append(self._cabecalho_soap())
        dados = etree.SubElement(raiz, 'nfseDadosMsg')
        dados.append(nota)
        # xml soap
        xml = self._construir_xml(raiz)

        retorno = self._post(url, xml)
        return retorno


    def _cabecalho_soap(self):
        u"""Monta o XML do cabeçalho da requisição SOAP"""

        raiz = etree.Element('nfseCabecMsg')
        cabecalho = etree.SubElement(raiz, 'cabecalho', xmlns=self._namespace, versao=self._versao)
        etree.SubElement(cabecalho, 'versaoDados').text = self._versao
        return raiz

    def _construir_xml(self, dados):
        """Mota o XML para o envio via SOAP"""

        raiz = etree.Element('{%s}Envelope'%NAMESPACE_SOAP, nsmap={'e': self._namespace})
        etree.SubElement(raiz, '{%s}Header'%NAMESPACE_SOAP)
        body = etree.SubElement(raiz, '{%s}Body'%NAMESPACE_SOAP)
        body.append(dados)
        return raiz


    def _get_url(self, autorizador):
        """ Retorna a url para comunicação com o webservice """
        if self._ambiente == 1:
            ambiente = 'HTTPS'
        else:
            ambiente = 'HOMOLOGACAO'
        if autorizador.upper() in NFSE:
            self.url = NFSE[autorizador.upper()][ambiente]
        else:
            raise Exception('Autorizador nao encontrado!')
        return self.url

    def _post(self, url, xml):
        certificadoA1 = CertificadoA1(self.certificado)
        chave, cert = certificadoA1.separar_arquivo(self.certificado_senha, caminho=True)
        chave_cert = (cert, chave)
        # Abre a conexão HTTPS
        try:
            xml_declaration='<?xml version="1.0" encoding="utf-8"?>'
            #xml = etree.tostring(xml, encoding='unicode', pretty_print=False).replace('\n','').replace('ns0:','soapenv:').replace(':ns0',':soapenv')
            xml = etree.tostring(xml, encoding='unicode', pretty_print=False).replace('\n','').replace('ns0:','').replace(':ns0','')
            xml = xml_declaration + xml

            print (xml)
            # Faz o request com o servidor
            #result = requests.post(url, xml, headers=self._post_header(), cert=chave_cert, verify=False)
            #result.encoding='utf-8'
            #return result
        except requests.exceptions.ConnectionError as e:
            raise e
        finally:
            certificadoA1.excluir()