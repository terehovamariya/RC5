class RC5Cipher {
  constructor(key, rounds = 12, wordSize = 64) {
    this.rounds = rounds;
    this.wordSize = parseInt(wordSize);
    this.blockSize = this.wordSize * 2;
    this.wordBytes = this.wordSize / 8;
    this.blockBytes = this.blockSize / 8;

    this.P = this.Q = 0;
    this.S = [];
    this._initConstants();
    this.setKey(key);
  }

  _initConstants() {
    if (this.wordSize === 64) {
      this.P = 0xb7e151628aed2a6bn;
      this.Q = 0x9e3779b97f4a7c15n;
    } else if (this.wordSize === 32) {
      this.P = 0xb7e15163;
      this.Q = 0x9e3779b9;
    }
  }

  setKey(key) {
    if (!key) key = "";

    const keyBytes = UTF8Utils.encode(key);
    const keyLength = keyBytes.length;

    const t = 2 * (this.rounds + 1);
    this.S = new Array(t);

    if (this.wordSize === 64) {
      this.S[0] = this.P;
      for (let i = 1; i < t; i++) {
        this.S[i] = (this.S[i - 1] + this.Q) & 0xffffffffffffffffn;
      }

      let L = [];
      for (let i = 0; i < keyLength; i += 8) {
        let word = 0n;
        for (let j = 0; j < 8 && i + j < keyLength; j++) {
          word |= BigInt(keyBytes[i + j]) << BigInt(j * 8);
        }
        L.push(word);
      }

      let A = 0n,
        B = 0n;
      let i = 0,
        j = 0;

      for (let k = 0; k < 3 * Math.max(t, L.length); k++) {
        this.S[i] = (this.S[i] + A + B) & 0xffffffffffffffffn;
        A = this._rotateLeft64((this.S[i] + A + B) & 0xffffffffffffffffn, 3);
        i = (i + 1) % t;

        if (L.length > 0) {
          L[j] = (L[j] + A + B) & 0xffffffffffffffffn;
          B = this._rotateLeft64(
            (L[j] + A + B) & 0xffffffffffffffffn,
            Number((A + B) & 0x3fn)
          );
          j = (j + 1) % L.length;
        }
      }
    } else {
      this.S[0] = this.P;
      for (let i = 1; i < t; i++) {
        this.S[i] = (this.S[i - 1] + this.Q) >>> 0;
      }
      let L = [];
      for (let i = 0; i < keyLength; i += 4) {
        let word = 0;
        for (let j = 0; j < 4 && i + j < keyLength; j++) {
          word |= keyBytes[i + j] << (j * 8);
        }
        L.push(word);
      }

      let A = 0,
        B = 0;
      let i = 0,
        j = 0;

      for (let k = 0; k < 3 * Math.max(t, L.length); k++) {
        this.S[i] = (this.S[i] + A + B) >>> 0;
        A = this._rotateLeft32((this.S[i] + A + B) >>> 0, 3);
        i = (i + 1) % t;

        if (L.length > 0) {
          L[j] = (L[j] + A + B) >>> 0;
          B = this._rotateLeft32((L[j] + A + B) >>> 0, (A + B) & 31);
          j = (j + 1) % L.length;
        }
      }
    }
  }

  _encryptBlock64(block) {
    if (block.length < 16) {
      const paddedBlock = new Uint8Array(16);
      paddedBlock.set(block);
      for (let i = block.length; i < 16; i++) {
        paddedBlock[i] = 0;
      }
      return this._encryptBlock64Internal(paddedBlock);
    }
    return this._encryptBlock64Internal(block);
  }

  _encryptBlock64Internal(block) {
    let A = 0n;
    let B = 0n;

    for (let i = 0; i < 8; i++) {
      A |= BigInt(block[i]) << BigInt(i * 8);
    }
    for (let i = 0; i < 8; i++) {
      B |= BigInt(block[i + 8]) << BigInt(i * 8);
    }

    A = (A + this.S[0]) & 0xffffffffffffffffn;
    B = (B + this.S[1]) & 0xffffffffffffffffn;

    for (let i = 1; i <= this.rounds; i++) {
      A =
        (this._rotateLeft64((A ^ B) & 0xffffffffffffffffn, Number(B & 0x3fn)) +
          this.S[2 * i]) &
        0xffffffffffffffffn;
      B =
        (this._rotateLeft64((B ^ A) & 0xffffffffffffffffn, Number(A & 0x3fn)) +
          this.S[2 * i + 1]) &
        0xffffffffffffffffn;
    }

    const result = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      result[i] = Number((A >> BigInt(i * 8)) & 0xffn);
    }
    for (let i = 0; i < 8; i++) {
      result[i + 8] = Number((B >> BigInt(i * 8)) & 0xffn);
    }

    return result;
  }

  _decryptBlock64(block) {
    if (block.length < 16) {
      const paddedBlock = new Uint8Array(16);
      paddedBlock.set(block);
      for (let i = block.length; i < 16; i++) {
        paddedBlock[i] = 0;
      }
      return this._decryptBlock64Internal(paddedBlock);
    }
    return this._decryptBlock64Internal(block);
  }

  _decryptBlock64Internal(block) {
    let A = 0n;
    let B = 0n;

    for (let i = 0; i < 8; i++) {
      A |= BigInt(block[i]) << BigInt(i * 8);
    }
    for (let i = 0; i < 8; i++) {
      B |= BigInt(block[i + 8]) << BigInt(i * 8);
    }

    for (let i = this.rounds; i >= 1; i--) {
      B =
        this._rotateRight64(
          (B - this.S[2 * i + 1]) & 0xffffffffffffffffn,
          Number(A & 0x3fn)
        ) ^ A;
      A =
        this._rotateRight64(
          (A - this.S[2 * i]) & 0xffffffffffffffffn,
          Number(B & 0x3fn)
        ) ^ B;
    }

    B = (B - this.S[1]) & 0xffffffffffffffffn;
    A = (A - this.S[0]) & 0xffffffffffffffffn;

    const result = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      result[i] = Number((A >> BigInt(i * 8)) & 0xffn);
    }
    for (let i = 0; i < 8; i++) {
      result[i + 8] = Number((B >> BigInt(i * 8)) & 0xffn);
    }

    return result;
  }

  _rotateLeft64(value, shift) {
    shift %= 64;
    return (
      ((value << BigInt(shift)) | (value >> BigInt(64 - shift))) &
      0xffffffffffffffffn
    );
  }

  _rotateRight64(value, shift) {
    shift %= 64;
    return (
      ((value >> BigInt(shift)) | (value << BigInt(64 - shift))) &
      0xffffffffffffffffn
    );
  }

  _rotateLeft32(value, shift) {
    shift %= 32;
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
  }

  _rotateRight32(value, shift) {
    shift %= 32;
    return ((value >>> shift) | (value << (32 - shift))) >>> 0;
  }

  _addPadding(data) {
    const blockSize = this.blockBytes;
    const paddingLength = blockSize - (data.length % blockSize);
    const padded = new Uint8Array(data.length + paddingLength);
    padded.set(data);

    for (let i = data.length; i < padded.length; i++) {
      padded[i] = paddingLength;
    }

    return padded;
  }

  _removePadding(data) {
    if (data.length === 0) return data;

    const paddingLength = data[data.length - 1];
    if (paddingLength > 0 && paddingLength <= this.blockBytes) {
      let valid = true;
      for (let i = data.length - paddingLength; i < data.length; i++) {
        if (data[i] !== paddingLength) {
          valid = false;
          break;
        }
      }
      if (valid) {
        return data.slice(0, data.length - paddingLength);
      }
    }

    return data;
  }

  encrypt(text) {
    const textBytes = UTF8Utils.encode(text);

    const paddedBytes = this._addPadding(textBytes);

    const iv = new Uint8Array(this.blockBytes);
    for (let i = 0; i < iv.length; i++) {
      iv[i] = Math.floor(Math.random() * 256);
    }

    const resultBlocks = [];
    let prevBlock = iv;

    for (let i = 0; i < paddedBytes.length; i += this.blockBytes) {
      let block = paddedBytes.slice(i, i + this.blockBytes);

      for (let j = 0; j < block.length; j++) {
        block[j] ^= prevBlock[j];
      }

      const encryptedBlock = this._encryptBlock64(block);
      resultBlocks.push(encryptedBlock);

      prevBlock = encryptedBlock;
    }

    const resultBytes = new Uint8Array(
      iv.length + resultBlocks.length * this.blockBytes
    );
    resultBytes.set(iv, 0);

    let offset = iv.length;
    for (const block of resultBlocks) {
      resultBytes.set(block, offset);
      offset += block.length;
    }

    return this._bytesToBase64(resultBytes);
  }

  decrypt(encryptedBase64) {
    const encryptedBytes = this._base64ToBytes(encryptedBase64);

    const iv = encryptedBytes.slice(0, this.blockBytes);
    const dataStart = this.blockBytes;

    const decryptedBlocks = [];
    let prevBlock = iv;

    for (let i = dataStart; i < encryptedBytes.length; i += this.blockBytes) {
      const block = encryptedBytes.slice(i, i + this.blockBytes);

      const decryptedBlock = this._decryptBlock64(block);

      for (let j = 0; j < decryptedBlock.length; j++) {
        decryptedBlock[j] ^= prevBlock[j];
      }

      decryptedBlocks.push(decryptedBlock);

      prevBlock = block;
    }

    const totalLength = decryptedBlocks.length * this.blockBytes;
    const decryptedBytes = new Uint8Array(totalLength);

    let offset = 0;
    for (const block of decryptedBlocks) {
      decryptedBytes.set(block, offset);
      offset += block.length;
    }

    const unpaddedBytes = this._removePadding(decryptedBytes);

    return UTF8Utils.decode(unpaddedBytes);
  }

  _bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  _base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  getHexString(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }
}
