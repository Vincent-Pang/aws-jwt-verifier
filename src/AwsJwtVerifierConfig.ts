export interface AwsJwtVerifierConfig
{
    jwksJson?: string;
    pems?: {[key: string]: string};
    tokenType: 'access' | 'id';
    iss: string;
}
