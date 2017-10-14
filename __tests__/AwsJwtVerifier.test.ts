import {AwsAccessToken, AwsIdToken, AwsJwtVerifier} from '../src/index';
import {Result} from 'result-class';
import * as MockDate from 'MockDate';

describe('Test AwsJwtVerifier.ts', () => {
    test('test verify ok', () => {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json, tokenType: 'access', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwODAwNjY1MCwiaWF0IjoxNTA4MDAzMDUwLCJ2ZXJzaW9uIjoyLCJqdGkiOiJlOWZjOWZmYi01ZWNlLTQ4NzUtOGMyMi00Mjc5N2UzNDhkMmEiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.DzDglG3WlynduwqA4B_7RWz1dMhM9pVDTfbmX425x2kCEuxSrKRgWT4V0tE4L2IjuNY_SFpURzI7mFIgTMyalju7GvHAawPuaauHPVB0OZOdTH9ctXfD-LMpgvXLcnl2sDMaxjNXcZW1dH3EifgT3Gx4Wfl_0k9_YLhYKxNsG42aEn-eKt0tV2Dr4lO_cTG2B-XxOHZO4aZlaN4zkdrtUTyMAr3YhVYgoPEVbp6SutparmV66TuQEMRQkibSWHaa22eKqyULW-mF1tOrcyWkfDGhxphhw9uzrwyOqBaSGVVM4uJGLEJF3dvmiFdAz9ATz17Z6Hd2Hx-Vz6VHs6MR9A';

        MockDate.set(1508003262977);
        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_ok()).toBeTruthy();

        MockDate.reset();
    });

    test('test verify fail - cannot decode jwt', () => {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json, tokenType: 'access', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = '123';

        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_err()).toBeTruthy();
        expect(result.unwrap_err()).toBe('Not a valid JWT token');
    });

    test('test verify fail - invalid iss', () => {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json, tokenType: 'access', iss: '1https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwNzkyNjg4MywiaWF0IjoxNTA3OTIzMjg0LCJ2ZXJzaW9uIjoyLCJqdGkiOiJmZDFmYzdkOC0zYmYwLTQwMzUtOGUwZC1mM2E1MTdhZmRmM2MiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.R9uTBj2NL3KL4_ymm-RHxWf3DozTPLWyy5clmuwPCtdsWDfZGwJiM5yQH3lguJbhNMy57aB0z2aSH3btBbfHozC5cbV1arTFwKd4ZWyUYPlbU8hg1WHqginYWGArT7SN4JRHxog_fVhICLbYgkGOQqYPNiA7yAQ7HJFNNGIpCjzVUufEWf4tgWN6Or6kV3CJHKRfmy2tlGCtzYlA4PT4UXSCTWHXuZh3BjnummS0hGhqp-suUKXGlCWptBm-xAuSKTPaa39GfVq53W8Zxc6p_13vupitGYi-ukqaUJBIVqwzycwiU2GSNqSNtWgtJthoIOGTZFuAsZiPD7wWvatQVQ';

        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_err()).toBeTruthy();
        expect(result.unwrap_err()).toBe('Invalid issuer');
    });

    test('test verify fail - kid of token is not as expected', () => {
        const json = `
            {
                "keys":[
                    {
                        "alg":"RS256",
                        "e":"AQAB",
                        "kid":"aaajkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=",
                        "kty":"RSA",
                        "n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw",
                        "use":"sig"
                    },
                    {
                        "alg":"RS256",
                        "e":"AQAB",
                        "kid":"aaaTlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=",
                        "kty":"RSA",
                        "n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw",
                        "use":"sig"
                    }
                ]
            }`;

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json, tokenType: 'access', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwODAwNjY1MCwiaWF0IjoxNTA4MDAzMDUwLCJ2ZXJzaW9uIjoyLCJqdGkiOiJlOWZjOWZmYi01ZWNlLTQ4NzUtOGMyMi00Mjc5N2UzNDhkMmEiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.DzDglG3WlynduwqA4B_7RWz1dMhM9pVDTfbmX425x2kCEuxSrKRgWT4V0tE4L2IjuNY_SFpURzI7mFIgTMyalju7GvHAawPuaauHPVB0OZOdTH9ctXfD-LMpgvXLcnl2sDMaxjNXcZW1dH3EifgT3Gx4Wfl_0k9_YLhYKxNsG42aEn-eKt0tV2Dr4lO_cTG2B-XxOHZO4aZlaN4zkdrtUTyMAr3YhVYgoPEVbp6SutparmV66TuQEMRQkibSWHaa22eKqyULW-mF1tOrcyWkfDGhxphhw9uzrwyOqBaSGVVM4uJGLEJF3dvmiFdAz9ATz17Z6Hd2Hx-Vz6VHs6MR9A';

        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_err()).toBeTruthy();
        expect(result.unwrap_err()).toBe('Invalid token');
    });

    test('test verify fail - invalid token type', () => {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json, tokenType: 'id', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwNzkyNjg4MywiaWF0IjoxNTA3OTIzMjg0LCJ2ZXJzaW9uIjoyLCJqdGkiOiJmZDFmYzdkOC0zYmYwLTQwMzUtOGUwZC1mM2E1MTdhZmRmM2MiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.R9uTBj2NL3KL4_ymm-RHxWf3DozTPLWyy5clmuwPCtdsWDfZGwJiM5yQH3lguJbhNMy57aB0z2aSH3btBbfHozC5cbV1arTFwKd4ZWyUYPlbU8hg1WHqginYWGArT7SN4JRHxog_fVhICLbYgkGOQqYPNiA7yAQ7HJFNNGIpCjzVUufEWf4tgWN6Or6kV3CJHKRfmy2tlGCtzYlA4PT4UXSCTWHXuZh3BjnummS0hGhqp-suUKXGlCWptBm-xAuSKTPaa39GfVq53W8Zxc6p_13vupitGYi-ukqaUJBIVqwzycwiU2GSNqSNtWgtJthoIOGTZFuAsZiPD7wWvatQVQ';

        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_err()).toBeTruthy();
        expect(result.unwrap_err()).toBe('Token type mismatch');
    });

    test('test verify fail - expired token', () => {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json, tokenType: 'access', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwNzkyNjg4MywiaWF0IjoxNTA3OTIzMjg0LCJ2ZXJzaW9uIjoyLCJqdGkiOiJmZDFmYzdkOC0zYmYwLTQwMzUtOGUwZC1mM2E1MTdhZmRmM2MiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.R9uTBj2NL3KL4_ymm-RHxWf3DozTPLWyy5clmuwPCtdsWDfZGwJiM5yQH3lguJbhNMy57aB0z2aSH3btBbfHozC5cbV1arTFwKd4ZWyUYPlbU8hg1WHqginYWGArT7SN4JRHxog_fVhICLbYgkGOQqYPNiA7yAQ7HJFNNGIpCjzVUufEWf4tgWN6Or6kV3CJHKRfmy2tlGCtzYlA4PT4UXSCTWHXuZh3BjnummS0hGhqp-suUKXGlCWptBm-xAuSKTPaa39GfVq53W8Zxc6p_13vupitGYi-ukqaUJBIVqwzycwiU2GSNqSNtWgtJthoIOGTZFuAsZiPD7wWvatQVQ';

        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_err()).toBeTruthy();
    });

    test('test config - missing both json and pems', () =>
    {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        expect( () => new AwsJwtVerifier({tokenType: 'access', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'}) ).toThrow();
    });

    test('test config - input pems', () => {
        // const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';
        const pems = {
            'jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=': '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAiAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhS\nsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn\n2KlmdH/DtvLiz1gxDlC8yyv8NwWy+igkb+VKHQHReMUpx/A6hbAm7Go6Gxne29dl\n1EehK98crMBbfWsHrBYoblx1QFsYr/s+IBJLHK4L1322AAJcrPOe0VC8jSnG1NPB\nBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3/6GGUPcM2kO8T0Xtwg\nZjlrmdbt4kypQLsbtzdNcoxYnve+dsjKqwIDAQAB\n-----END RSA PUBLIC KEY-----\n',
            'TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=': '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAiGV8eel+S1aP4tKl+W+uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePV\nUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N/+\ns1wqMEmG1Ir0hkIZLFoeP6ol/AW0kB324ytRJ8yvTe5kIcJw/BRjX99kkIqHWcVD\nvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYY\nVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX/NwrbQDzE/4ImWBodnzrwqoSZd0G3\nXQuN3sOwwdmec0//Kl22/JFgFmFDIA4NrwIDAQAB\n-----END RSA PUBLIC KEY-----\n'
        };

        const awsJwtVerifier = new AwsJwtVerifier({pems, tokenType: 'access', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwODAwNjY1MCwiaWF0IjoxNTA4MDAzMDUwLCJ2ZXJzaW9uIjoyLCJqdGkiOiJlOWZjOWZmYi01ZWNlLTQ4NzUtOGMyMi00Mjc5N2UzNDhkMmEiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.DzDglG3WlynduwqA4B_7RWz1dMhM9pVDTfbmX425x2kCEuxSrKRgWT4V0tE4L2IjuNY_SFpURzI7mFIgTMyalju7GvHAawPuaauHPVB0OZOdTH9ctXfD-LMpgvXLcnl2sDMaxjNXcZW1dH3EifgT3Gx4Wfl_0k9_YLhYKxNsG42aEn-eKt0tV2Dr4lO_cTG2B-XxOHZO4aZlaN4zkdrtUTyMAr3YhVYgoPEVbp6SutparmV66TuQEMRQkibSWHaa22eKqyULW-mF1tOrcyWkfDGhxphhw9uzrwyOqBaSGVVM4uJGLEJF3dvmiFdAz9ATz17Z6Hd2Hx-Vz6VHs6MR9A';

        MockDate.set(1508003262977);
        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_ok()).toBeTruthy();

        MockDate.reset();
    });

    test('test config - input both pems and json, pems should be used', () => {
        const invalidJson = `
            {
                "keys":[
                    {
                        "alg":"aaaRS256",
                        "e":"aaaAQAB",
                        "kid":"aaajkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=",
                        "kty":"aaaRSA",
                        "n":"aaaiAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw",
                        "use":"aaasig"
                    },
                    {
                        "alg":"bbbRS256",
                        "e":"bbbAQAB",
                        "kid":"bbbTlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=",
                        "kty":"bbbRSA",
                        "n":"bbbiGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw",
                        "use":"bbbsig"
                    }
                ]
            }`;

        const pems = {
            'jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=': '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAiAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhS\nsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn\n2KlmdH/DtvLiz1gxDlC8yyv8NwWy+igkb+VKHQHReMUpx/A6hbAm7Go6Gxne29dl\n1EehK98crMBbfWsHrBYoblx1QFsYr/s+IBJLHK4L1322AAJcrPOe0VC8jSnG1NPB\nBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3/6GGUPcM2kO8T0Xtwg\nZjlrmdbt4kypQLsbtzdNcoxYnve+dsjKqwIDAQAB\n-----END RSA PUBLIC KEY-----\n',
            'TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=': '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAiGV8eel+S1aP4tKl+W+uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePV\nUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N/+\ns1wqMEmG1Ir0hkIZLFoeP6ol/AW0kB324ytRJ8yvTe5kIcJw/BRjX99kkIqHWcVD\nvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYY\nVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX/NwrbQDzE/4ImWBodnzrwqoSZd0G3\nXQuN3sOwwdmec0//Kl22/JFgFmFDIA4NrwIDAQAB\n-----END RSA PUBLIC KEY-----\n'
        };

        const awsJwtVerifier = new AwsJwtVerifier({pems, jwksJson: invalidJson, tokenType: 'access', iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwODAwNjY1MCwiaWF0IjoxNTA4MDAzMDUwLCJ2ZXJzaW9uIjoyLCJqdGkiOiJlOWZjOWZmYi01ZWNlLTQ4NzUtOGMyMi00Mjc5N2UzNDhkMmEiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.DzDglG3WlynduwqA4B_7RWz1dMhM9pVDTfbmX425x2kCEuxSrKRgWT4V0tE4L2IjuNY_SFpURzI7mFIgTMyalju7GvHAawPuaauHPVB0OZOdTH9ctXfD-LMpgvXLcnl2sDMaxjNXcZW1dH3EifgT3Gx4Wfl_0k9_YLhYKxNsG42aEn-eKt0tV2Dr4lO_cTG2B-XxOHZO4aZlaN4zkdrtUTyMAr3YhVYgoPEVbp6SutparmV66TuQEMRQkibSWHaa22eKqyULW-mF1tOrcyWkfDGhxphhw9uzrwyOqBaSGVVM4uJGLEJF3dvmiFdAz9ATz17Z6Hd2Hx-Vz6VHs6MR9A';

        MockDate.set(1508003262977);
        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_ok()).toBeTruthy();

        MockDate.reset();
    });

    test('test config - missing tokenType, \'access\' will be used', () => {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json, iss: 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_fLK8LlWlm'});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwODAwNjY1MCwiaWF0IjoxNTA4MDAzMDUwLCJ2ZXJzaW9uIjoyLCJqdGkiOiJlOWZjOWZmYi01ZWNlLTQ4NzUtOGMyMi00Mjc5N2UzNDhkMmEiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.DzDglG3WlynduwqA4B_7RWz1dMhM9pVDTfbmX425x2kCEuxSrKRgWT4V0tE4L2IjuNY_SFpURzI7mFIgTMyalju7GvHAawPuaauHPVB0OZOdTH9ctXfD-LMpgvXLcnl2sDMaxjNXcZW1dH3EifgT3Gx4Wfl_0k9_YLhYKxNsG42aEn-eKt0tV2Dr4lO_cTG2B-XxOHZO4aZlaN4zkdrtUTyMAr3YhVYgoPEVbp6SutparmV66TuQEMRQkibSWHaa22eKqyULW-mF1tOrcyWkfDGhxphhw9uzrwyOqBaSGVVM4uJGLEJF3dvmiFdAz9ATz17Z6Hd2Hx-Vz6VHs6MR9A';

        MockDate.set(1508003262977);
        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_ok()).toBeTruthy();

        MockDate.reset();
    });

    test('test config - missing iss, empty str will be used', () => {
        const json = '{"keys":[{"alg":"RS256","e":"AQAB","kid":"jkQynUQIVBCd+JGf6zw6KjTePDkrQ6MYlVVRxZVzSe0=","kty":"RSA","n":"iAyY4vghvPGWEsJJ0L0vBSAJ4SWK6PUUBbNnDEHrqJC5FSZe7ZhSsk8JqqFKDMXFqIGnFCmCk6nqhYoLFEmzU2GxDiujWsLy6nw7mEVqtBvtdtObqqIn2KlmdH_DtvLiz1gxDlC8yyv8NwWy-igkb-VKHQHReMUpx_A6hbAm7Go6Gxne29dl1EehK98crMBbfWsHrBYoblx1QFsYr_s-IBJLHK4L1322AAJcrPOe0VC8jSnG1NPBBCcbC0245chIgjCqXAATze30d0qisQJ3awWHz8A5sCqWy3_6GGUPcM2kO8T0XtwgZjlrmdbt4kypQLsbtzdNcoxYnve-dsjKqw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TlIHImDQXBbDMv2UgW5FAMS2ePhT8lPGoh9znv7XuWs=","kty":"RSA","n":"iGV8eel-S1aP4tKl-W-uXlbolNnZwZkeuXPU1lmwIUTYGGYHfePVUhKKxXXl5epSKa0ko5TXGXAmMuSNNtai6DNbGwDCTImP11Dsq83kj9Y0OZrS2N_-s1wqMEmG1Ir0hkIZLFoeP6ol_AW0kB324ytRJ8yvTe5kIcJw_BRjX99kkIqHWcVDvHOWp9tGSJReMpTlvu8PUF72L41mMQzxYNCnHXON0qxQzfcZCoOAaLOFiFZQXvYYVNkOcO53Ri3O51aZU0NdDNqUVAVKjGqGaIX_NwrbQDzE_4ImWBodnzrwqoSZd0G3XQuN3sOwwdmec0__Kl22_JFgFmFDIA4Nrw","use":"sig"}]}';

        const awsJwtVerifier = new AwsJwtVerifier({jwksJson: json});

        const token = 'eyJraWQiOiJUbElISW1EUVhCYkRNdjJVZ1c1RkFNUzJlUGhUOGxQR29oOXpudjdYdVdzPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZDEzMmRjNC1kOWY5LTQwZGQtYmMxZS02MWQ4MWUxZTExMDUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb21cL2FwLW5vcnRoZWFzdC0xX2ZMSzhMbFdsbSIsImV4cCI6MTUwODAwNjY1MCwiaWF0IjoxNTA4MDAzMDUwLCJ2ZXJzaW9uIjoyLCJqdGkiOiJlOWZjOWZmYi01ZWNlLTQ4NzUtOGMyMi00Mjc5N2UzNDhkMmEiLCJjbGllbnRfaWQiOiIzMHN1NGdjbDJxMTlra3V1YXNlMW5iOTNkaSIsInVzZXJuYW1lIjoiR29vZ2xlXzEwMzY3MDU4ODE3Nzc1NTY4MDU3NyJ9.DzDglG3WlynduwqA4B_7RWz1dMhM9pVDTfbmX425x2kCEuxSrKRgWT4V0tE4L2IjuNY_SFpURzI7mFIgTMyalju7GvHAawPuaauHPVB0OZOdTH9ctXfD-LMpgvXLcnl2sDMaxjNXcZW1dH3EifgT3Gx4Wfl_0k9_YLhYKxNsG42aEn-eKt0tV2Dr4lO_cTG2B-XxOHZO4aZlaN4zkdrtUTyMAr3YhVYgoPEVbp6SutparmV66TuQEMRQkibSWHaa22eKqyULW-mF1tOrcyWkfDGhxphhw9uzrwyOqBaSGVVM4uJGLEJF3dvmiFdAz9ATz17Z6Hd2Hx-Vz6VHs6MR9A';

        MockDate.set(1508003262977);
        const result: Result<AwsAccessToken | AwsIdToken, string> = awsJwtVerifier.verify(token);

        expect(result.is_err()).toBeTruthy();
        expect(result.unwrap_err()).toBe('Invalid issuer');

        MockDate.reset();
    });
});
