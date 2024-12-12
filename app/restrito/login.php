<?php
  include('../bd.php');
  $erro = 0;

  if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $usuario = mysqli_real_escape_string($conn,$_POST["usuario"]);
    $senha = mysqli_real_escape_string($conn,$_POST["senha"]);

    if (!empty($usuario) && !empty($senha)) {
      $sql = "select * from usuarios where usuario='$usuario'";
      $result = mysqli_query($conn, $sql);

      if (mysqli_num_rows($result) > 0) {
        $row = mysqli_fetch_assoc($result);
        $tipo = $row["tipo"];
        $hash_armazenado = $row["senha"]; 
        $senha_valida = password_verify($senha, $hash_armazenado);
       if ($senha_valida) {
          session_start();
          $_SESSION["autenticado"] = "sim";

          if ($tipo == "A") {
            header("Location: painel_alunos.php");
            $_SESSION["tipo"] = "A";
          } else {
            header("Location: painel_professores.php");
            $_SESSION["tipo"] = "P";
          }
          exit();  
        } else {
          $erro = 1;
        }
      } else {
        $erro = 1; 
      }
      mysqli_close($conn);
    } else {
      $erro = 1;
    }
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
      <div class="column cl-100 text-left">
        <h1>Sistema Acadêmico</h1>
      </div>
    </div>
  </div>
</header>

<!-- Main -->
<section class="section-gap">
  <div class="container-login">
    <div class="card-auth">
      <h2>Login</h2>
      <hr style="margin-bottom: 20px;">
      <form class="form-login" action="<?php echo $_SERVER["PHP_SELF"];?>" method="POST">
        <label>Usuário</label>
        <input type="text" id="usuario" name="usuario" placeholder="Informe o usuário" maxlength="10" required>
        <label>Senha</label>
        <input type="password" id="senha" name="senha" placeholder="Informe a senha" maxlength="8" required>
        <div class="text-right">
          <button type="submit" style="width: 100%; margin-bottom: 20px;" name="btnlogin">Acessar</button>
          <hr>
        </div>
      </form>
<?php
  if ($erro == 1) {
?>
      <div style="padding-top: 20px;">
        <blockquote class="blockquote">Usuário e/ou senha inválidos</blockquote>
      </div>
<?php
  }
?>
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