# STIXParser

Este é um conversor de ficheiros .csv para JSON em formato STIX.
Foi feito no ambito de facilitar a conversão de tabelas csv de IPs, Dominios e _File Hashes_ para a inserção da mesma na maioria das fabricantes de _Firewall_.
Isto é uma conversão _"Best Effort"_ ,sendo que poderam ser necessario ação manual no ficheiro de Output (Ainda não foi testado em Hardware Fisico)

Atualmente, esta apto para gerar ficheiros STIX de versão 2, esta por implementar o output de versão 1 do STIX.

# Como Funciona?

Esta configurado para ler ficheiros .csv com o seguinte formato:

**IP|Dominio|Hash/Ação**
é que os converte em um ficheiro .json com o formato STIX v2.

Relembro novamente que só é possivel fazer uma conversão _"Best Effort"_, sendo que podera ser necessario interveção no ficheiro para este se tornar "legivel" para a Firewall.
