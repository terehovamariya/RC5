const UTF8Utils = {
  encode: function (str) {
    if (typeof TextEncoder !== "undefined") {
      return new TextEncoder().encode(str);
    }

    const utf8 = [];
    for (let i = 0; i < str.length; i++) {
      let charCode = str.charCodeAt(i);

      if (charCode < 0x80) {
        utf8.push(charCode);
      } else if (charCode < 0x800) {
        utf8.push(0xc0 | (charCode >> 6));
        utf8.push(0x80 | (charCode & 0x3f));
      } else if (charCode < 0xd800 || charCode >= 0xe000) {
        utf8.push(0xe0 | (charCode >> 12));
        utf8.push(0x80 | ((charCode >> 6) & 0x3f));
        utf8.push(0x80 | (charCode & 0x3f));
      } else {
        i++;
        charCode =
          0x10000 + (((charCode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
        utf8.push(0xf0 | (charCode >> 18));
        utf8.push(0x80 | ((charCode >> 12) & 0x3f));
        utf8.push(0x80 | ((charCode >> 6) & 0x3f));
        utf8.push(0x80 | (charCode & 0x3f));
      }
    }

    return new Uint8Array(utf8);
  },

  decode: function (bytes) {
    if (typeof TextDecoder !== "undefined") {
      return new TextDecoder("utf-8").decode(bytes);
    }

    let str = "";
    let i = 0;

    while (i < bytes.length) {
      let charCode = bytes[i];

      if (charCode < 0x80) {
        str += String.fromCharCode(charCode);
        i++;
      } else if (charCode >= 0xc0 && charCode < 0xe0) {
        if (i + 1 < bytes.length) {
          charCode = ((charCode & 0x1f) << 6) | (bytes[i + 1] & 0x3f);
          str += String.fromCharCode(charCode);
          i += 2;
        } else {
          i++;
        }
      } else if (charCode >= 0xe0 && charCode < 0xf0) {
        if (i + 2 < bytes.length) {
          charCode =
            ((charCode & 0x0f) << 12) |
            ((bytes[i + 1] & 0x3f) << 6) |
            (bytes[i + 2] & 0x3f);
          str += String.fromCharCode(charCode);
          i += 3;
        } else {
          i++;
        }
      } else if (charCode >= 0xf0) {
        if (i + 3 < bytes.length) {
          charCode =
            ((charCode & 0x07) << 18) |
            ((bytes[i + 1] & 0x3f) << 12) |
            ((bytes[i + 2] & 0x3f) << 6) |
            (bytes[i + 3] & 0x3f);
          charCode -= 0x10000;
          str += String.fromCharCode(0xd800 + (charCode >> 10));
          str += String.fromCharCode(0xdc00 + (charCode & 0x3ff));
          i += 4;
        } else {
          i++;
        }
      } else {
        i++;
      }
    }

    return str;
  },
};
