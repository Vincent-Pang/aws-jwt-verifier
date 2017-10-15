# aws-jwt-verifier

A library to verify AWS jwt when using AWS user pool.

## Installation

```
yarn add aws-jwt-verifier
```

## API

### class AwsJwtVerifier

#### `constructor(config: AwsJwtVerifierConfig)`

##### `config`
```
{
    // the content of jwks.json
    // the json can be found at https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
    // either jwksJson or pems must be set,
    // if both are set, pems will be used.
    jwksJson?: string;
    
    // the jwksJson above will be transform to pems finally,
    // you can input pems directly in order to save the jwkToPem transformation.
    // either jwksJson or pems must be set,
    // if both are set, pems will be used.
    pems?: {[key: string]: string};
    
    // specify the type of token which will be passed into the function verify(token)
    // 'access': access token
    // 'id': id token
    // 'access' will be used if this is not specified
    tokenType?: 'access' | 'id';
    
    // issuer
    // it should be something like https://cognito-idp.{region}.amazonaws.com/{userPoolId}
    iss?: string;
}
```

#### `verify(token: string): Result<AwsAccessToken | AwsIdToken, string>`

##### token: string
If config.tokenType is 'access', please pass in access token.  
If config.tokenType is 'id', please pass in id token.  

##### return `Result<AwsAccessToken | AwsIdToken, string>`
If success, decoded jwt will be returned. Otherwise, error will be returned.  
The raw data is wrapped with [result-class](https://github.com/Vincent-Pang/result-class).  

## Usage

Init AwsJwtVerifier
```
const json = '{"keys":[{"alg":"RS256", xxxxx}';

const config: AwsJwtVerifierConfig = {
    jwksJson: json,
    tokenType: 'access',
    iss: 'https://cognito-idp.{region}.amazonaws.com/{userPoolId}'
};

const awsJwtVerifier = new AwsJwtVerifier(config);
```

Verify token
```
const token = 'xxxxxxx';

const result = awsJwtVerifier.verify(token);

if (result.is_ok())
    console.log(result.unwrap());   // decoded jwt
else
    console.log(result.unwrap_err());   // error msg
```

## Reference

This library is implemented according to these documents.  
* http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html 
* https://aws.amazon.com/blogs/mobile/integrating-amazon-cognito-user-pools-with-api-gateway/

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
