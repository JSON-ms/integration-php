<?php

/**
 * Configurations: You can change
 */
$secretKey = '28c96e7c3e240b71422751a1';
$cypherKey = '662fd00533a2285b9bb49297';
$accessControlAllowOrigin = 'http://localhost:3000';
$publicFilePath = 'https://local.demo.json.ms/files/';

/**
 * Script: CHANGE AT YOUR OWN RISKS
 */

// Function to handle errors and send appropriate HTTP response
function throwError($code, $body) {
    http_response_code($code || 500);
    echo json_encode(['body' => $body]);
    exit;
}

// Function to generate a random hash of a given length
function generateHash($length = 10): string {
    $bytes = random_bytes($length);
    $result = bin2hex($bytes);
    return substr($result, 0, $length);
}

// Custom error handler function
function customErrorHandler($errno, $errstr, $errfile, $errline) {
    http_response_code(500);
    echo json_encode(['body' => "[$errno]: $errstr in $errfile on line $errline"]);
    exit();
}
set_error_handler("customErrorHandler");

// Custom exception handler function
function customExceptionHandler($exception) {
    http_response_code(500);
    echo json_encode(['body' => $exception->getMessage()]);
    exit();
}
set_exception_handler("customExceptionHandler");

// Shutdown function to handle fatal errors
function shutdownFunction() {
    $error = error_get_last();
    if ($error) {
        http_response_code(500);
        echo json_encode(['body' => $error['message']]);
        exit();
    }
}
register_shutdown_function('shutdownFunction');

// Function to decrypt encrypted data using the provided encryption key
function decrypt($encryptedData, $encryptionKey) {
    $arr = explode('::', base64_decode($encryptedData), 2);
    if (count($arr) != 2) {
        return false;
    }
    list($encryptedData, $iv) = $arr;
    return openssl_decrypt($encryptedData, 'AES-256-CBC', $encryptionKey, 0, $iv);
}

/**
 * CORS and HTTP Headers Configuration
 */

// Define allowed origins for cross-origin requests
$allowedOrigins = explode(',', $accessControlAllowOrigin);
$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

// Check if the origin is in the allowed origins and set CORS headers
if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
}
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Jms-Api-Key, X-Jms-Interface-Hash");
header("Access-Control-Allow-Credentials: true");
header('Content-Type: application/json');

// Handle OPTIONS request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(204);
    exit;
}

/**
 * API Key Validation and Request Handling
 */

// Get the headers from the request
$headers = getallheaders();

// Validate if the API Key is provided and correct
if (!isset($headers['X-Jms-Api-Key'])) {
    throwError(401, 'API Secret Key not provided');
} elseif (decrypt($headers['X-Jms-Api-Key'], $cypherKey) !== $secretKey) {
    throwError(401, 'Invalid API Secret Key');
}

/**
 * File Upload and Directory Setup
 */

// Check if a file is being uploaded
$hasFile = isset($_FILES['file']);
$privatePath = dirname(__FILE__) . '/private/';
$dataPath = $privatePath . 'data/';
$interfacePath = $privatePath . 'interfaces/';
$uploadDir = $privatePath . 'files/';
$serverSettings = [
    "uploadMaxSize" => ini_get('upload_max_filesize'),
    "postMaxSize" => ini_get('post_max_size'),
    'publicUrl' => $publicFilePath,
];

// Create directories if they do not exist
if (!is_dir($interfacePath)) {
    mkdir($interfacePath, 0755, true);
}
if (!is_dir($dataPath)) {
    mkdir($dataPath, 0755, true);
}
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

/**
 * Handling GET Request: Retrieve JSON Data
 */

// Handle GET request to fetch data
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    http_response_code(200);
    $dataFilePath = $dataPath . $_GET['hash'] . '.json';
    $interfaceFilePath = $interfacePath . $_GET['hash'] . '.json';
    $data = [];
    $interface = [];
    if (file_exists($dataFilePath)) {
        $data = json_decode(file_get_contents($dataFilePath));
    }
    if (file_exists($interfaceFilePath)) {
        $interface = json_decode(file_get_contents($interfaceFilePath));
    }
    echo json_encode([
        'data' => $data,
        'interface' => $interface,
        'settings' => $serverSettings,
    ]);
    exit;
}

/**
 * Handling File Upload: POST Request
 */

// Handle file upload with POST request
else if ($hasFile && $_SERVER['REQUEST_METHOD'] === 'POST') {

    // Check if Interface hash is provided in the headers
    if (!isset($headers['X-Jms-Interface-Hash'])) {
        throwError(400, 'Interface hash not provided.');
    }

    // Handle errors related to file upload
    if ($_FILES['file']['error'] != UPLOAD_ERR_OK) {
        switch ($_FILES['file']['error']) {
            case UPLOAD_ERR_INI_SIZE:
                throwError(400, "Error: The uploaded file exceeds the maximum file size limit.");
                break;
            case UPLOAD_ERR_FORM_SIZE:
                throwError(400, "Error: The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form.");
                break;
            case UPLOAD_ERR_PARTIAL:
                throwError(400, "Error: The uploaded file was only partially uploaded.");
                break;
            case UPLOAD_ERR_NO_FILE:
                throwError(400, "Error: No file was uploaded.");
                break;
            case UPLOAD_ERR_NO_TMP_DIR:
                throwError(400, "Error: Missing a temporary folder.");
                break;
            case UPLOAD_ERR_CANT_WRITE:
                throwError(400, "Error: Failed to write file to disk.");
                break;
            case UPLOAD_ERR_EXTENSION:
                throwError(400, "Error: A PHP extension stopped the file upload.");
                break;
            default:
                throwError(400, "Error: Unknown upload error.");
                break;
        }
    }
    // Process the file upload if no errors
    else {

        $fileTmpPath = $_FILES['file']['tmp_name'];
        $fileName = $_FILES['file']['name'];
        $fileSize = $_FILES['file']['size'];
        $fileType = $_FILES['file']['type'];
        $extension = pathinfo($fileName, PATHINFO_EXTENSION);

        // Specify the directory where the file will be saved
        $destPath = $uploadDir . $headers['X-Jms-Interface-Hash'] . '-' . generateHash(16) . '.' . $extension;

        // Move the uploaded file to the destination directory
        if (move_uploaded_file($fileTmpPath, $destPath)) {
            $internalPath = str_replace($uploadDir, '', $destPath);
            http_response_code(200);
            echo json_encode([
                'success' => true,
                'publicPath' => $publicFilePath . $internalPath,
                'internalPath' => $internalPath,
            ]);
            exit;
        } else {
            throwError(400, 'There was an error moving the uploaded file.');
        }
    }
}

/**
 * Handling JSON Creation or Update: POST Request
 */

// Handle POST request for creating or updating JSON files
else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $json = file_get_contents('php://input');
    $data = (object) json_decode($json, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        throwError(400, 'Invalid JSON');
    }

    // Save the data and interface to JSON files
    file_put_contents(
        $dataPath . $data->hash . '.json',
        json_encode($data->data)
    );
    file_put_contents(
        $interfacePath . $data->hash . '.json',
        json_encode($data->interface)
    );
    http_response_code(200);
    echo json_encode($data);
    exit;
}

// End the script
die;
