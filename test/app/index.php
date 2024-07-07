<?php

require_once 'config.php';
require_once 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$key = 'secret_key';
$algorithm = 'HS256';

function connectDB() {
    global $config;
    
    $host = $config['host'];
    $dbname = $config['dbname'];
    $user = $config['username'];
    $password = $config['password'];
    
    $dsn = "pgsql:host=$host;dbname=$dbname";
    
    try {
        $pdo = new PDO($dsn, $user, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        echo 'Connection failed: ' . $e->getMessage();
        return null;
    }
}

function createJWT($userId, $email) {
    global $key, $algorithm;
    $payload = [
        'iss' => 'your_iss',
        'aud' => 'your_aud',
        'iat' => time(),
        'nbf' => time(),
        'exp' => time() + (60 * 60),
        'data' => [
            'id' => $userId,
            'email' => $email,
        ]
    ];
    return JWT::encode($payload, $key, $algorithm);
}

function decodeJWT($jwt) {
    global $key, $algorithm;
    try {
        $decoded = JWT::decode($jwt, new Key($key, $algorithm));
        return (array) $decoded->data;
    } catch (Exception $e) {
        return null;
    }
}


// Аутентификация 
function authenticate() {
    $headers = apache_request_headers();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Неавториозован"]);
        exit();
    }
    $token = str_replace('Bearer ', '', $headers['Authorization']);
    $decoded = decodeJWT($token);
    if (!$decoded) {
        http_response_code(401);
        echo json_encode(["error" => "Неавториозован"]);
        exit();
    }
    return $decoded;
}

// Создание пользователя
function createUser($name, $email, $password) {
    $pdo = connectDB();

    // валидация
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ["error" => "Формат email не верен"];
    }
    
    // Проверка уникальности email
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        return ["error" => "Email уже занят"];
    }
    
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    if ($stmt->execute([$name, $email, $hashed_password])) {
        return ["success" => "Пользователь успешно создан"];
    } else {
        return ["error" => "Ошибка создания пользователя"];
    }
}

// получение списка пользователей с сортировкой и фильтрацией
function getUsers($filter = null, $sort = null) {
    $pdo = connectDB();
    
    $query = "SELECT * FROM users";
    $params = [];
    
    if ($filter) {
        $field = $filter['field'];
        $operator = $filter['operator'];
        $value = $filter['value'];
        
        $validOperators = ['=', '<', '>', '<=', '>='];
        if (!in_array($operator, $validOperators)) {
            return ["error" => "Invalid operator"];
        }
        
        $query .= " WHERE $field $operator ?";
        $params[] = $value;
    }
    
    if ($sort) {
        $sortField = $sort['field'];
        $sortOrder = strtoupper($sort['order']) === 'DESC' ? 'DESC' : 'ASC';
        
        $query .= " ORDER BY $sortField $sortOrder";
    }
    
    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Изменение информации пользователя
function updateUser($id, $name, $email) {
    $pdo = connectDB();
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ["error" => "Формат email не верен"];
    }

    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
    $stmt->execute([$id]);
    if (!$stmt->fetch()) {
        return ["error" => "Пользователь не найден"];
    }
    
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
    $stmt->execute([$email, $id]);
    if ($stmt->fetch()) {
        return ["error" => "Email уже занят"];
    }

    $stmt = $pdo->prepare("UPDATE users SET name = ?, email = ? WHERE id = ?");
    if ($stmt->execute([$name, $email, $id])) {
        return ["success" => "Изменение данных успешно"];
    } else {
        return ["error" => "Ошибка изменения данных"];
    }
}

// Удаление пользователя
function deleteUser($id) {
    $pdo = connectDB();
    
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    if ($stmt->execute([$id])) {
        return ["success" => "Пользователь успешно удален"];
    } else {
        return ["error" => "Ошибка удаления пользователя"];
    }
}

function loginUser($email, $password) {
    $pdo = connectDB();

    $stmt = $pdo->prepare("SELECT id, password FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password'])) {
        $token = createJWT($user['id'], $email);
        return ["token" => $token];
    } else {
        return ["error" => "Не верно введенные данные"];
    }
}


//маршруты
$request_method = $_SERVER['REQUEST_METHOD'];

switch ($request_method) {
    case 'GET':
        if (!empty($_GET["action"])) {
            $action = $_GET["action"];
            switch ($action) {
                case 'getUsers':
                    authenticate(); 
                    if (!empty($_GET["filter"])) {
                        $filter = json_decode($_GET["filter"], true);
                    } else {
                        $filter = null;
                    }
                    if (!empty($_GET["sort"])) {
                        $sort = json_decode($_GET["sort"], true);
                    } else {
                        $sort = null;
                    }
                    echo json_encode(getUsers($filter, $sort));
                    break;
            }
        }
        break;
    case 'POST':
        if (!empty($_GET["action"])) {
            $action = $_GET["action"];
            switch ($action) {
                case 'createUser':
                    $data = json_decode(file_get_contents('php://input'), true);
                    echo json_encode(createUser($data['name'], $data['email'], $data['password']));
                    break;
                case 'authenticate':
                    $data = json_decode(file_get_contents('php://input'), true);
                    echo json_encode(loginUser($data['email'], $data['password']));
                    break;
            }
        }
        break;
    case 'PUT':
        authenticate(); 
        if (!empty($_GET["action"])) {
            $action = $_GET["action"];
            switch ($action) {
                case 'updateUser':
                    $data = json_decode(file_get_contents('php://input'), true);
                    echo json_encode(updateUser($data['id'], $data['name'], $data['email']));
                    break;
            }
        }
        break;
    case 'DELETE':
        authenticate(); 
        if (!empty($_GET["action"])) {
            $action = $_GET["action"];
            switch ($action) {
                case 'deleteUser':
                    $data = json_decode(file_get_contents('php://input'), true);
                    echo json_encode(deleteUser($data['id']));
                    break;
            }
        }
        break;
}

?>
