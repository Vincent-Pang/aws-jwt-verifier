# aws-jwt-verifier

A library to verify AWS jwt when using AWS user pool.

## Installation

```
yarn add aws-jwt-verifier
```

## Usage

Init AwsJwtVerifier.
```
// paste the content of jwks.json here
// https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
const json = '{"keys":[{"alg":"RS256", xxxxx}';

const config: AwsJwtVerifierConfig = {
    jwksJson: json,
    tokenType: 'access',    // either 'access' or 'id' for access token or id token
    iss: 'https://cognito-idp.{region}.amazonaws.com/{userPoolId}'
};

const awsJwtVerifier = new AwsJwtVerifier(config);
```

Verify token
```
const token = 'xxxxxxx';

// pass 'access' token to verify
const result = awsJwtVerifier.verify(token);

if (result.is_ok())
    console.log(result.unwrap());
else
    console.log(result.unwrap_err());
```

If you want to know how to verify a token, please refer to the following documents.
http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html  
https://aws.amazon.com/blogs/mobile/integrating-amazon-cognito-user-pools-with-api-gateway/

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
