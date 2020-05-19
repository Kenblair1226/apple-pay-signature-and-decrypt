# Apple pay payment token signature validation and decryption

[![npm version](https://img.shields.io/npm/dt/apple-pay-signature-and-decrypt.svg?style=flat-square)](https://img.shields.io/npm/dt/apple-pay-signature-and-decrypt.svg)
[![npm version](https://img.shields.io/npm/v/apple-pay-signature-and-decrypt.svg?style=flat-square)](https://www.npmjs.com/package/apple-pay-signature-and-decrypt)

A node app to handle apple pay payment token signature validation and decryption

ref: [Payment Token Format Reference](https://developer.apple.com/library/archive/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html)

## Getting started  
```sh
npm i --save apple-pay-signature-and-decrypt
```

You will need to create a merchant id and payment processing certificate on apple developer site. Details described [here](https://help.apple.com/developer-account/#/devb2e62b839?sub=dev103e030bb). After that you will get the merchant certificate and private key.


## Usage

```js
const requestToken = {
    "data": "<encryptedData>",
    "version": "EC_v1",
    "signature": "<signature>",
    "header": {
        "ephemeralPublicKey": "<ephemeralPublicKey>",
        "publicKeyHash": "<publicKeyHash>",
        "transactionId": "<transactionId>"
    }
}

const publicCert = fs.readFileSync(path.join(__dirname, './publicCert.pem'), 'utf8') // import your certificate file
const privateKey = fs.readFileSync(path.join(__dirname, './privateKey.pem'), 'utf8') // import your private key file

const token = new applePayPaymentToken(requestToken)
const decryptedToken = token.decrypt(publicCert, privateKey)
decryptedToken.then( ret => {
    console.log(ret)
}).catch( err => {
    console.error(err)
})
```

#### Sample output
```js
{
    "applicationExpirationDate": "231231",
    "applicationPrimaryAccountNumber": "4802********4384",
    "currencyCode": "901",
    "deviceManufacturerIdentifier": "0400*****273",
    "paymentDataType": "3DSecure",
    "transactionAmount": 89900,
    "paymentData": {
        "eciIndicator": "7",
        "onlinePaymentCryptogram": "Aj+W784****************MAABAAA="
}
```