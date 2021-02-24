const content = document.getElementById("content");
const hash_input = document.getElementById("hash_input");
const hash_form = document.getElementById("hash_form");

function decrypt(passphrase = hash_input.value) {
    hash_input.value = "";
    if (CryptoJS.SHA512(passphrase) == hash) {
        let decrypted = CryptoJS.AES.decrypt(encrypted, CryptoJS.SHA256(passphrase), { mode: CryptoJS.mode.ECB }).toString(CryptoJS.enc.Utf8);
        hash_form.style = "display: none;";
        content.innerHTML = marked(decrypted);
        content.style = "";
    } else {
        alert("Incorrect hash! Please try again!")
    }
}

function get_parameters() {
    const urlParams = new URLSearchParams(window.location.search);
    const passphrase = urlParams.get("p");
    if (passphrase != null) {
        decrypt(passphrase);
    }
}

get_parameters();