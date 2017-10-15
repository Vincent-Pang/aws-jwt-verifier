import {AwsJwtVerifierConfig} from './AwsJwtVerifierConfig';
import {Err, Ok, Result} from 'result-class';
import {Builder} from 'builder-pattern';
import {AwsJwksJson} from './AwsJwksJson';
import * as jwkToPem from 'jwk-to-pem';
import * as jsonwebtoken from 'jsonwebtoken';
import {AwsAccessToken} from './AwsAccessToken';
import {AwsIdToken} from './AwsIdToken';

export class AwsJwtVerifier
{
    private config: Readonly<AwsJwtVerifierConfig>;
    private pems: {[key: string]: string};

    public constructor(config: AwsJwtVerifierConfig)
    {
        this.config = this.genConfig(config);

        if (this.config.pems && this.config.jwksJson)
        {
            this.pems = this.config.pems;
        }
        else if (this.config.pems)
        {
            this.pems = this.config.pems;
        }
        else if (this.config.jwksJson)
        {
            this.pems = this.genPemsByJson(this.config.jwksJson);
        }
        else
        {
            throw Error('AwsJwtVerifier: Neither pem nor jwksJson is set');
        }
    }

    private genConfig(config: AwsJwtVerifierConfig): AwsJwtVerifierConfig
    {
        const configBuilder = Builder<AwsJwtVerifierConfig>();

        configBuilder
            .jwksJson(config.jwksJson)
            .pems(config.pems)
            .tokenType(config.tokenType ? config.tokenType : 'access')
            .iss(config.iss ? config.iss : '');

        return configBuilder.build();
    }

    private genPemsByJson(jwksJson: string): {[key: string]: string}
    {
        const jwksObj: AwsJwksJson = JSON.parse(jwksJson);

        const pems: {[key: string]: string} = {};

        jwksObj.keys
            .forEach(v =>
            {
                const jwk = {
                    kty: v.kty  // key_type
                    , n: v.n    // modulus
                    , e: v.e    // exponent
                };

                const pem = jwkToPem(jwk);

                pems[v.kid] = pem;
            });

        return pems;
    }

    public verify(token: string): Result<AwsAccessToken | AwsIdToken, string>
    {
        const decoded: AwsAccessToken | AwsIdToken | null = jsonwebtoken.decode(token, {complete: true}) as any;

        // Fail if the token is not jwt
        if (!decoded)
        {
            return new Err('Not a valid JWT token');
        }

        // Fail if token is not from your User Pool
        if (decoded.payload.iss !== this.config.iss)
        {
            return new Err('Invalid issuer');
        }

        // Reject the jwt if it's not an 'Access Token' or 'Id Token'
        if (decoded.payload.token_use !== this.config.tokenType)
        {
            return new Err('Token type mismatch');
        }

        // Get the kid from the token and retrieve corresponding PEM
        const pem = this.pems[decoded.header.kid];

        if (!pem)
        {
            return new Err('Invalid token');
        }

        try
        {
            jsonwebtoken.verify(token, pem, { issuer: this.config.iss });
        }
        catch (err)
        {
            return new Err(err);
        }

        return new Ok(decoded);
    }
}
