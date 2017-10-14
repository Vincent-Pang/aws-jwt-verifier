export interface AwsIdToken
{
    header: {
        kid: string;
        alg: string;
    };

    payload: {
        sub: string;
        aud: string;
        'cognito:groups': string[];

        identities: [{
            userId: string;
            providerName: string;
            providerType: string;
            issuer: string;
            primary: string;
            dateCreated: string;
        }];

        token_use: string;
        auth_time: number;
        iss: string;
        name: string;
        'cognito:username': string;
        exp: number;
        iat: number;
        email: string;
    };
}
