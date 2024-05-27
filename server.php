<?php

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

// Fonction pour lire le contenu d'un fichier
function readFileContent($filePath) {
    if (!file_exists($filePath)) {
        throw new Exception("File not found: $filePath");
    }
    return file_get_contents($filePath);
}

try {
    // Lecture du contenu du fichier chiffré en base64
    $msgReq = readFileContent('message.request.txt');
    $lastPointIndex = strrpos($msgReq, '.');
    $clientId = substr($msgReq, 0, $lastPointIndex);
    $cipherText = substr($msgReq, $lastPointIndex + 1);

    // Mot de passe utilisé pour déchiffrer le contenu
    $password = strtoupper(readFileContent("password.txt"));

    echo "Loaded datas: $msgReq - $clientId - $cipherText - $password" ;
    // Déchiffrement du contenu
    $decryptedContent = aes256ecb_decrypt(base64_decode($cipherText), $password);

    // Affichage du contenu déchiffré
    echo "Contenu déchiffré de " . $clientId . " :\n" . $decryptedContent;
} catch (Exception $e) {
    echo "Erreur : " . $e->getMessage();
}

?>
