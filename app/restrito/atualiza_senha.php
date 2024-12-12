<?php
include('../bd.php');

$options = [
  'cost' => 11,
];

$senha = mysqli_real_escape_string($conn, $_POST['senha']);
$usuario = mysqli_real_escape_string($conn,$_POST["usuario"]);
$hash = password_hash($senha, PASSWORD_BCRYPT, $options);
$sql = "UPDATE usuarios SET senha='$hash' where usuario='$usuario'";
if ($conn->query($sql) === TRUE) {
  echo "Atualizado com sucesso";
} else {
  echo "Erro ao atualizar" . $conn->error;
}
?>