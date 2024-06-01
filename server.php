<?php

$exitCode = 50;

function aes256ecb_decrypt($cipherText, $password) {
    $cipher = 'aes-256-ecb';

    // Dérivation de la clé en utilisant SHA-256
    $key = hash('sha256', $password, true);

    // Déchiffrement
    $decrypted = openssl_decrypt($cipherText, $cipher, $key, OPENSSL_RAW_DATA);

    if ($decrypted === false) {
        throw new Exception("Decryption failed.");
    }

    return $decrypted;
}

function aes256cbc_encrypt($clearText, $password, $ivBlockBinary) {
    $cipher = 'aes-256-cbc';

    // Dérivation de la clé en utilisant SHA-256
    $key = hash('sha256', $password, true);

    // Déchiffrement
    $encrypted = openssl_encrypt($clearText, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $ivBlockBinary);

    if ($encrypted === false) {
        throw new Exception("Encryption failed.");
    }

    return $encrypted;
}

// Fonction pour lire le contenu d'un fichier
function readFileContent($filePath) {
    if (!file_exists($filePath)) {
        throw new Exception("File not found: $filePath");
    }
    return file_get_contents($filePath);
}

function writeFileContent($filePath, $content) {
    if (file_put_contents($filePath, $content) === false) {
        throw new Exception("Failed to write to file: $filePath");
    }
}

try {
    // Lecture du contenu du fichier chiffré en base64
    $msgReq = readFileContent('exchange/message.request.txt');
    $lastPointIndex = strrpos($msgReq, '.');
    $clientId = substr($msgReq, 0, $lastPointIndex);
    $cipherText = substr($msgReq, $lastPointIndex + 1);

    // Mot de passe utilisé pour déchiffrer le contenu
    $password = strtoupper(readFileContent("params/password.hex"));

    echo "Loaded datas: $msgReq - $clientId - $cipherText - $password" ;
    // Déchiffrement du contenu
    $decryptedContent = aes256ecb_decrypt(base64_decode($cipherText), $password);

    // Affichage du contenu déchiffré
    echo "Contenu déchiffré de " . $clientId . " :\n" . $decryptedContent . "\n";

    $msg = json_decode($decryptedContent, true);
    echo "Request timestamp = " . $msg['timestamp'] . "\n";
    echo "Request idClient = " . $msg['idClientRappel'] . "\n";
    echo "Request package = " . $msg['request']['package'] . "\n";
    echo "Request ivBlock = " . $msg['request']['ivBlock'] . "\n";

    $ivBlock = base64_decode($msg['request']['ivBlock']);

    $answer['package'] = $msg['request']['package'];
    $answer['key1'] = 'value1';
    $answer['key2'] = 'value2';
    $response = json_encode($answer, true);
    echo "JSON answer is:\n" . $response . "\n";

    $encryptedAnswered = base64_encode(aes256cbc_encrypt($response, $password, $ivBlock));
    echo "Answered ciphered is:\n" . $encryptedAnswered . "\n";

    writeFileContent("exchange/message.answer.b64", $encryptedAnswered);

    $exitCode = 200;
} catch (Exception $e) {
    echo "Erreur : " . $e->getMessage();
}

exit($exitCode);

?>

