<?php
  session_start();

  if(empty($_SESSION["autenticado"])) {
    session_destroy();
    header("Location: login.php");
    
  }
  if ($_SESSION["tipo"] !="A"){
    echo "Usuário não permitido";
  exit();
    

    


    }

    

    
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <title>Sistema Acadêmico</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://fonts.googleapis.com/css?family=Poppins:100,200,400,300,500,600,700" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
  <link href="../css/styles.css" rel="stylesheet">
</head>
<body>

<!-- Header -->
<header class="header">
  <div class="container">
    <div class="row">
      <div class="column cl-100">
        <h1>Sistema Acadêmico</h1>
      </div>
    </div>
  </div>
</header>

<!-- Main -->
<section class="section-gap">
  <div class="container">
    <h2 class="text-center">Painel de Alunos</h2>
    <br>
    <div class="row">
      <div class="column cl-100 column-content">
        <a href="javascript:void(0)">
          <div class="card">
            <p class="text-center"><strong>Recurso/conteúdo ABC (restrito aos alunos)</strong></p>
          </div>
        </a>
      </div>
    </div>
    <div class="row">
      <div class="column cl-100 column-content">
        <a href="logout.php">
          <div class="card">
            <p class="text-center"><strong>Encerrar Sessão</strong></p>
          </div>
        </a>
      </div>
    </div>
  </div>
</section>

<!-- Footer -->
<footer class="footer">
  <div class="container">
    <div class="row">
      <div class="column cl-100 text-center">
        <p>Segurança da Informação. Exemplo de Aula: Aplicação Web Vulnerável</p>
      </div>
    </div>
  </div>
</footer>

</body>
</html>