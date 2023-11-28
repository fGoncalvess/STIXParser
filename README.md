# STIXParser

Este é um conversor de ficheiros .csv para JSON em formato STIX.
Foi feito no ambito de facilitar a conversão de tabelas csv de IPs, Dominios e _File Hashes_ para a inserção da mesma na maioria das fabricantes de _Firewall_.
Isto é uma conversão _"Best Effort"_ ,sendo que poderam ser necessario ação manual no ficheiro de Output (Ainda não foi testado em Hardware Fisico)

Atualmente, esta apto para gerar ficheiros STIX de versão 2, esta por implementar o output de versão 1 do STIX.

# Como Funciona?

Esta configurado para ler ficheiros .csv sobre o formato do CNCS, que é:

Antes de usar será necessaria a instalação do Python. Este parser foi desenvolvido com a versão 3.10, o minimo recomendado será 3.6.
Depois de fazer o clone ao repositorio, vai ser necessario o seguinte comando, para fazer a instalação de todas as dependencias:
  pip install -r requirements.txt

**IP|Dominio|Hash/Ação**
é que os converte em um ficheiro .json com o formato STIX v2 ou em formato .xml para suporte STIX v1.

Relembro novamente que só é possivel fazer uma conversão _"Best Effort"_, sendo que podera ser necessario interveção no ficheiro para este se tornar "legivel" para a Firewall.
