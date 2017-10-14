export interface AwsJwksJson
{
    keys: [{
        alg: string
        , e: string
        , kid: string
        , kty: string
        , n: string
        , use: string
    }];
}
