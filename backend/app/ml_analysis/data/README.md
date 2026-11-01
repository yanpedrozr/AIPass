# Listas de senhas comuns

Uma senha por linha. As duas listas são lidas juntas por `features.py`, sem diferenciar maiúsculas, para os atributos `is_common_password` e `common_substring_length`.

| Arquivo | Conteúdo | Origem |
|---------|----------|--------|
| `10k-most-common.txt` | As 10.000 senhas mais comuns em geral (predominantemente em inglês) | [SecLists](https://github.com/danielmiessler/SecLists), `Passwords/Common-Credentials/10k-most-common.txt` |
| `Portugese_Pwdb_common-password-list-top-150.txt` | As 150 senhas mais comuns em português (ex.: `123mudar`, `flamengo`, `senha123`, `deusefiel`) | [SecLists](https://github.com/danielmiessler/SecLists), `Passwords/Common-Credentials/Language-Specific/`, originada do projeto [Pwdb-Public](https://github.com/ignis-sec/Pwdb-Public) |

- **Licença:** MIT (SecLists e Pwdb-Public)
- **Baixadas em:** 28/09/2026
- Os nomes dos arquivos foram mantidos como na origem (inclusive a grafia "Portugese").

# Base de treino

| Arquivo | Conteúdo |
|---------|----------|
| `rockyou-sample.txt` | 100.000 senhas sorteadas da RockYou (semente 42) |
| `training-labels.csv` | A amostra rotulada: `password`, `zxcvbn_score`, `label`, `label_code`. Gerado por `dataset.py`, fora do git |

- **Origem da RockYou:** [SecLists](https://github.com/danielmiessler/SecLists), `Passwords/Leaked-Databases/rockyou.txt.tar.gz` (≈14 milhões de senhas distintas, vazadas em 2009). Baixada em 28/09/2026. O arquivo completo (140 MB) não fica no projeto.
- **Separação das listas dos atributos:** nenhuma senha da amostra está nas listas acima, comparando sem diferenciar maiúsculas. Variantes que não estão nas listas, como `p@ssw0rd`, podem aparecer.
- **Filtros:** linhas que não são UTF-8 válido, com caracteres de controle ou com mais de 64 caracteres foram descartadas.
- **Distribuição dos rótulos:** fraca 35.685 (35,7%), média 36.499 (36,5%), forte 27.816 (27,8%).
