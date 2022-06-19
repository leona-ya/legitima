function isWebAuthnSupported() {
  return window.PublicKeyCredential !== undefined && typeof window.PublicKeyCredential === "function"
}

function getLabel() {
  let answer = prompt('Please enter a label for the WebAuthn device you want to register');
  return answer === '' ? getLabel() : answer
}

function webAuthnRegister() {
  if (!isWebAuthnSupported()) {
    alert("Sorry, WebAuthn is not supported by your browsers")
    return
  }
  let label = getLabel();
  if (label === null) {
    return
  }
  fetch("/selfservice/security/webauthn/challenge_register", {
    method: "POST",
    credentials: 'same-origin',
    body: JSON.stringify({ "label": label }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then(res => {
    if (res.status != 200) {
      alert("There is an internal error. Try again later.")
      throw new Error("Opps");
    }
    return res;
  })
    .then(res => res.json())
    .then(response => {
      const challenge = response.cc;
      challenge.publicKey.challenge = fromBase64(challenge.publicKey.challenge);
      challenge.publicKey.user.id = fromBase64(challenge.publicKey.user.id);
      return navigator.credentials.create(challenge).then(newCredential => {
        const cc = {};
        cc.id = newCredential.id;
        cc.rawId = toBase64(newCredential.rawId);
        cc.response = {};
        cc.response.attestationObject = toBase64(newCredential.response.attestationObject);
        cc.response.clientDataJSON = toBase64(newCredential.response.clientDataJSON);
        cc.type = newCredential.type;
        fetch("/selfservice/security/webauthn/register/" + response.id, {
          method: "POST",
          body: JSON.stringify(cc),
          headers: {
            "Content-Type": "application/json",
          },
        }).then(res => {
          if (res.status != 200) {
            alert("There is an internal error. Try again later.")
            throw new Error("Opps");
          }
          document.location.reload()
        })
      })
    })
}

function toBase64(data) {
  let b64val = btoa(String.fromCharCode.apply(null, new Uint8Array(data)));
  return b64val.replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
}

function fromBase64(data) {
  let fixed = data.replace(/_/g, '/').replace(/-/g, '+');
  while (fixed.length % 4 !== 0) {
    fixed += "=";
  }
  return toArray(atob(fixed));
}

function toArray(str) {
  return Uint8Array.from(str, c => c.charCodeAt(0));
}

