<?php
  include('../bd.php');
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
      <div class="column cl-100 text-left">
        <h1>Sistema Acadêmico</h1>
      </div>
    </div>
  </div>
</header>

<!-- Main -->
<section class="section-gap">
  <div class="container">
    <div class="row">
      <div class="column cl-100">
        <h2 class="text-center">Pesquisa de Cursos</h2>
        <br>
        <form class="formulario" action="<?php echo $_SERVER["PHP_SELF"];?>" method="GET">
          <label for="fname">Nome do Curso:</label><br>
          <input type="text" placeholder="Exemplo: Análise e Desenvolvimento de Sistemas" name="search">
          <button type="submit">Pesquisar</button>
        </form>
      </div>
    </div>
<?php
  if(isset($_GET["search"]) and !empty($_GET["search"])) {
    $search = mysqli_real_escape_string($conn, $_GET["search"]);
    $sql = "SELECT * FROM cursos WHERE nome LIKE '%$search%'";
    $result = mysqli_query($conn, $sql);
?>
    <div class="row">
      <br>
      <p style="margin: 0;"><strong>Resultado da pesquisa por: </strong><?php echo $search; ?></p>
      <br>
    </div>
<?php
      if (mysqli_num_rows($result) > 0) {
?>
    <div class="row">
      <div class="column cl-100">
        <table id="tabela">
          <tr>
            <th>Nome</th>
            <th>Nível</th>
            <th>Duração</th>
            <th>Período</th>
          </tr>
<?php
      while($row = mysqli_fetch_assoc($result)) {
        $nome = $row["nome"];
        $nivel = $row["nivel"];
        $duracao= $row["duracao"];
        $periodo = $row["periodo"];
?>
          <tr>
            <td><?php echo $nome; ?></td>
            <td><?php echo $nivel; ?></td>
            <td><?php echo $duracao; ?></td>
            <td><?php echo $periodo; ?></td>
          </tr>
<?php
      }
    }
    mysqli_close($conn);
?>
        </table>
      </div>
    </div>
<?php
  }
?>
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