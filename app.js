let rc5 = null;
let lastEncrypted = null;

function updateStatus(message, isError = false) {
  const statusDiv = document.getElementById("status");
  statusDiv.textContent = message;
  statusDiv.className = `status-indicator ${
    isError ? "status-error" : "status-good"
  }`;
}

function encryptText() {
  try {
    const text = document.getElementById("text").value;
    const key = document.getElementById("key").value;
    const rounds = parseInt(document.getElementById("rounds").value);
    const wordSize = parseInt(document.getElementById("blockSize").value);

    if (!key) {
      updateStatus("Ошибка: введите ключ", true);
      return;
    }

    if (rounds < 1 || rounds > 255) {
      updateStatus("Ошибка: количество раундов должно быть от 1 до 255", true);
      return;
    }

    rc5 = new RC5Cipher(key, rounds, wordSize);

    if (wordSize === 32) {
      updateStatus("32-битный режим требует отдельной реализации", true);
      return;
    }

    const encrypted = rc5.encrypt(text);
    lastEncrypted = encrypted;

    document.getElementById("encryptedResult").textContent = encrypted;
    document.getElementById("decryptedResult").textContent =
      'Нажмите "Расшифровать" для дешифрования';

    const encryptedBytes = rc5._base64ToBytes(encrypted);
    document.getElementById(
      "encryptedHex"
    ).textContent = `HEX: ${rc5.getHexString(encryptedBytes)}`;
    document.getElementById("decryptedHex").textContent = "";

    updateStatus(
      `✓ Текст зашифрован успешно (${rounds} раундов, ${wordSize} бит)`
    );
  } catch (error) {
    updateStatus("Ошибка при шифровании: " + error.message, true);
    console.error(error);
  }
}

function decryptText() {
  try {
    const key = document.getElementById("key").value;
    const rounds = parseInt(document.getElementById("rounds").value);
    const wordSize = parseInt(document.getElementById("blockSize").value);

    if (!rc5 || !lastEncrypted) {
      updateStatus("Ошибка: сначала зашифруйте текст", true);
      return;
    }

    if (!key) {
      updateStatus("Ошибка: введите ключ", true);
      return;
    }

    rc5 = new RC5Cipher(key, rounds, wordSize);

    if (wordSize === 32) {
      updateStatus("32-битный режим требует отдельной реализации", true);
      return;
    }

    const decrypted = rc5.decrypt(lastEncrypted);

    document.getElementById("decryptedResult").textContent = decrypted;

    const decryptedBytes = UTF8Utils.encode(decrypted);
    document.getElementById(
      "decryptedHex"
    ).textContent = `HEX: ${rc5.getHexString(decryptedBytes)}`;

    updateStatus(`✓ Текст расшифрован успешно`);
  } catch (error) {
    updateStatus("Ошибка при дешифровании: " + error.message, true);
    console.error(error);
  }
}

function init() {
  updateStatus("Готов к работе.");

  const exampleText =
    "Это тестовое сообщение для демонстрации работы шифра RC5";
  document.getElementById("text").value = exampleText;
}

window.onload = init;
