function isWebAuthnSupported() {
  return window.PublicKeyCredential !== undefined && typeof window.PublicKeyCredential === "function"
}

function webAuthnLogin() {
  if (!isWebAuthnSupported()) {
    alert("Sorry, WebAuthn is not supported by your browsers")
    return
  }
  fetch("/auth/webauthn_2fa/challenge_login", {
    method: "GET", credentials: 'same-origin',
  }).then(res => {
    if (res.status != 200) {
      alert("There is an internal error. Try again later.")
      throw new Error("Opps");
    }
    return res;
  })
    .then(res => res.json())
    .then(response => {
      console.log(response);
      const challenge = response.cc;
      challenge.publicKey.challenge = fromBase64(challenge.publicKey.challenge);
      challenge.publicKey.allowCredentials = challenge.publicKey.allowCredentials.map(c => {
        c.id = fromBase64(c.id)
        return c
      });
      return navigator.credentials.get(challenge)
        .then(credentials => {
          const pk = {};
          pk.id = credentials.id;
          pk.rawId = toBase64(credentials.rawId);
          pk.response = {};
          pk.response.authenticatorData = toBase64(credentials.response.authenticatorData);
          pk.response.clientDataJSON = toBase64(credentials.response.clientDataJSON);
          pk.response.signature = toBase64(credentials.response.signature);
          pk.response.userHandle = toBase64(credentials.response.userHandle);
          pk.type = credentials.type;

          return fetch("/auth/webauthn_2fa/login/" + response.id, {
            method: "POST", body: JSON.stringify(pk), headers: {
              "Content-Type": "application/json",
            },
          })
            .then(res => {
              if (res.status != 200) {
                alert("There is an internal error. Try again later.")
                throw new Error("Opps");
              }
              return res.text()
            })
            .then((res) => {
              window.location.replace(res)
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

webAuthnLogin();
