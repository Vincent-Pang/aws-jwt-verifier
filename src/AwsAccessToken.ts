export interface AwsAccessToken
{
    header: {
        kid: string;
        alg: string;
    };

    payload: {
        sub: string;
        token_use: string;
        scope: string;
        iss: string;
        exp: number;
        iat: number;
        version: number;
        jti: string;
        client_id: string;
        username: string;
    };
}
