/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.JWT;
import org.zaproxy.addon.migt.ParsingException;

public class JWT_Test {
    JWT j;
    String raw_jwt =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    String raw_header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
    String raw_payload =
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
    String raw_signature =
            "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    String public_pem_ed =
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPq3ZL01cG1DHZ4iZLiRlRJIlupb5MGfHipSBq1hG2Jo=\n-----END PUBLIC KEY-----\n";
    String private_pem_ed =
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFlqmiu8kHunEywNZhbZjdZcT1YGTUCoOlh9aHF+43UE\n-----END PRIVATE KEY-----\n";

    String private_pem_rsa =
            "-----BEGIN RSA PRIVATE KEY-----\n"
                    + "MIIJKQIBAAKCAgEAlD5LtoIK0+dFO2bEaGWRdK3yO4BXOty05yv61WTJO8l8gl1X\n"
                    + "LoQZS35bXYmsrh/4a58Wr+d2KrFx71ZzBrx0hJsJ/5+Ia+9q7zUCAmyuv+A73e/k\n"
                    + "kf/CIRSyg2tq++etsFoyUtx8AEw7IrGcLzhvy4R4h2vmgtqaln7Nw55FoLKJ8QiE\n"
                    + "Tq9UPz9KiV3OhA6ks07y6Brj63fCv6G9sX7uxDoflxVTiH7CaimlLv0h0hrA8s1O\n"
                    + "D3VfZjsKIGP+bTtsGzeBzGhxPCkg5DRGTRM/ST1OBMe3Swf9/kZ0ZsbcM2RliEVi\n"
                    + "OigVm4gYoVyIHbt+/Sig438qcrc581w1jdOzvmrPjXRlj60iKBjXnhPwT8UGZn4O\n"
                    + "WFu9NypVSfMjHgAIdEs+rOVp0YDxPhRU41DbRXci7TefZmCguaoir+7S7em5vPVO\n"
                    + "73fnYFrTEKTGdhlsYo43t5I9NkWlRZigg3UsdSREDZCdBlDcPx7UQDiBs9u3Uh4+\n"
                    + "2RT7R/Cdp4aPihq2lI4+iWVUk51xdWRJHeI4vbUYj3bwn4OrkXsb0PgzSz2Ss84f\n"
                    + "VIsFd6oLprxQn2OOj5Ra6P3ZpoosSvyD4J8zVZGUhi4sHzKDL3B7/wHTjXvHYbRW\n"
                    + "kWnvde7YV7aHMY+RlT+4LscDozIYRp5fPoh/DLNWfy8zTwGDWiiZGrB9RrcCAwEA\n"
                    + "AQKCAgA0R2PcETBQWpcHw84wIuGRDGcIpNIeaAdEHzZuWwS8mOnX76L3PI7PGNiP\n"
                    + "vCWxooSxL4GIt0/s7ncHuK0ICx3sReDYzSIHLn+/rCnxQPK/qAx00E0DT/beQ7ZQ\n"
                    + "smkgPSv7rVNh9W+lizyvl4NFA9opI6Z924eHTiCGQmG+Quq7KTuMTTyboylKxL88\n"
                    + "gmB6Ic/jjEwNnq4SNEHx4tBK8ECz4uuRFGxJDqrxVY5za8GpntW8yrpkqTfjjZ6c\n"
                    + "nab0TqhpUMHtnEeSt85prCW+uLLw2TXSabwyMbdZHO+f7zFozlcgH5fseoZkOzK0\n"
                    + "dTVrhtvZ26IhmI8XtZYyRKp+QdJ5IwF3XpXWt7zafUdYCu8Z45HZhEe+aTpNIDvv\n"
                    + "z2nkqiJ0zAMH188YqbgawCdWow6D3/vqoyr5IlZcj9qE2wKunT5eqr248rNQsLA5\n"
                    + "2nOwz4fPcN4RHyiBygD8G4867di7Q+qRBdMAfRx5DrG0ottL2oNrr5G9Wv94Dsu8\n"
                    + "+A0q8EpwAvwYsxCNVnrjd2ypfJhyS30Pktz/LWj/MWbee1BP83C3zveqwBQ+zxTd\n"
                    + "03surmBlNS7tZOZvThMbBlWIO66wQWCzkZwi6zbrJwHCf4B30jTepERsiLSv2jyI\n"
                    + "oHNGOa84i2IEdWtXGVVyAET9E+pzNVQjFHsembIS6H1W4GTjwQKCAQEAzkB4lLkx\n"
                    + "6gm5o5IhRC2ZAL9RaZGSrT9sXJThtq7qVqQiLItvNRa633eqfxzlkgBgmH2dGgc+\n"
                    + "OqZMOHE2u0PSWBUinkrzatFTyjn99H6jYtG70rxLMZcS9GD5padP2mFklrM9+WaN\n"
                    + "f7fuvZjsiIanVxhykyEqB7y43JSR5vUSab9tltbnG2+V2ZMmh+8GWEDwozhyOZW9\n"
                    + "cjhu+eI+7FqyU1JBydArO3Ds8ZpWrjfZvxmS7LzoJEkJ4hdfMmeAWFNv+tLhYGAT\n"
                    + "Et7d6atoxPL6bId+F+ncqgCF9SVmYpq9faoXsvOr7yxR3n6MLY5Fvz2fX0tvBeSv\n"
                    + "skn/a1mei1yqHQKCAQEAt//yZzEjCgi49QeT01CHPbkogbtkG+tVuB5V2zpLArj1\n"
                    + "AXXKSNZn96+UjgScEY/DTWm8ljjDP8UYZXmYgkBm+oEdYnyLa60u/ZSdP4E1ICJT\n"
                    + "32XHrbkt1Z9SdMDFwhitKuA9uyUIuLf2OfIvZQQDU6BPmr18OX82ODxZXqCMdGJH\n"
                    + "3rml16joa5u9KDPNLfei2NEEKc9L7szvtBwQYf2DKd4jgpZMOg8EFQBd3+szl7UD\n"
                    + "gTPRT7sZX035mNYfZkFTjj0z4vqEu1ARCkKz0fp05uEQnQLOTUGEgECDTh7jZnfn\n"
                    + "PDDio4/vW8qEPEfUcfpetbNr3i8hhAeA5xHyBij74wKCAQEAvPo1gY9uPJJMlaL+\n"
                    + "+AkPd6/UWHYZfsPt9aY0ab462MfqyAW6D1qUPszWW0GO1wehehceKwsX6YUVsWGK\n"
                    + "VGr//9Tds0vZXLYPn+si1TJzYcfp4FzGSNmzdFamZzG16NHz6GCzGCDu5WcSSIYl\n"
                    + "s7ItAZBU6pooeI5ikzlNteA2zs2nC948Qtcq5f/9/e70UUivM940Sq74tf8fL7Yt\n"
                    + "EULIwa9MuC0Ub5I4h+ZyJY7m5EH6bQ9pZFXHyHDBuN08q7FHmPo/pp5g25l4mvGD\n"
                    + "PXGkImzDDAYrOVjhZIywEwjVNp7yt/SsRKjHGqW4qsUBAwjjTd1ADJZMpX9HmIS0\n"
                    + "z9xHwQKCAQEAp3O0LHuIcupLQRvbSZXg7qhil+ZtjgcXZM+evTwI5fpjZyfGp5EQ\n"
                    + "31YYcUL6sfTO/dW7vk78Sj3aHQeTZv6reVEl5+qGi8D5oeetUA0LxynWgNnE5nI/\n"
                    + "p0kupniFwUXp2rpnE7j5ffpViJjCz0Desi2UJLRLqJwAQR+TCc485PJIjAcSSfk7\n"
                    + "RCtg84RpN2tF9eIK0u4IIdS6VYSw2Cz6QJEcagzUZIYj5eUGifEoa+ldvijlVZVl\n"
                    + "2tlAzPoZa1sKasmCPhBV2Y5dY6QeuHsiBrhPAUV7cM2ug3WyydbMhwWaGKo4qDgm\n"
                    + "0re0rpOEYRJFPUGDapoj+19EzYYEZ9zGlwKCAQBdOy3ctg82hG8y2GR2S8abgVI1\n"
                    + "b9S4s8FOYxxujzM6nkB+m8J1el4Sk8n4HuYDY9kivfI9/sbR7wUX9fV0QJHlr70t\n"
                    + "z8aTKNQVxzGzO+OLEGs66ieAI8uCOByCEbyqPUZZAg0YN7BWtfFsqdAwOdEdYCMO\n"
                    + "CR0axKnVhkIV7Oj9JQ1+mucB8gL5N8miSxc9lsWuOz2tGEM8rcTAoGSmvwMkgcfK\n"
                    + "P34FFHdGk4fZnRYA6pGfgVZD3ZyRYF9cWnNgw823JlsYhzGGX4pQbFFGZ4rGuQ9z\n"
                    + "ursu/oNFRzKSZrb1FHOHvv5DfkINWXPVL8EgQG2HN2AF+LSZllSrStef9Urw\n"
                    + "-----END RSA PRIVATE KEY-----";

    String public_pem_rsa =
            "-----BEGIN PUBLIC KEY-----\n"
                    + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlD5LtoIK0+dFO2bEaGWR\n"
                    + "dK3yO4BXOty05yv61WTJO8l8gl1XLoQZS35bXYmsrh/4a58Wr+d2KrFx71ZzBrx0\n"
                    + "hJsJ/5+Ia+9q7zUCAmyuv+A73e/kkf/CIRSyg2tq++etsFoyUtx8AEw7IrGcLzhv\n"
                    + "y4R4h2vmgtqaln7Nw55FoLKJ8QiETq9UPz9KiV3OhA6ks07y6Brj63fCv6G9sX7u\n"
                    + "xDoflxVTiH7CaimlLv0h0hrA8s1OD3VfZjsKIGP+bTtsGzeBzGhxPCkg5DRGTRM/\n"
                    + "ST1OBMe3Swf9/kZ0ZsbcM2RliEViOigVm4gYoVyIHbt+/Sig438qcrc581w1jdOz\n"
                    + "vmrPjXRlj60iKBjXnhPwT8UGZn4OWFu9NypVSfMjHgAIdEs+rOVp0YDxPhRU41Db\n"
                    + "RXci7TefZmCguaoir+7S7em5vPVO73fnYFrTEKTGdhlsYo43t5I9NkWlRZigg3Us\n"
                    + "dSREDZCdBlDcPx7UQDiBs9u3Uh4+2RT7R/Cdp4aPihq2lI4+iWVUk51xdWRJHeI4\n"
                    + "vbUYj3bwn4OrkXsb0PgzSz2Ss84fVIsFd6oLprxQn2OOj5Ra6P3ZpoosSvyD4J8z\n"
                    + "VZGUhi4sHzKDL3B7/wHTjXvHYbRWkWnvde7YV7aHMY+RlT+4LscDozIYRp5fPoh/\n"
                    + "DLNWfy8zTwGDWiiZGrB9RrcCAwEAAQ==\n"
                    + "-----END PUBLIC KEY-----";

    String raw_jwe =
            "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.df14swiSheMDVazjpF60-Vi1Qk46HBJtVhlBOhnAeouJGu0Qf5q_-ENHNVC0ur7pza3n0o3dUodgx_vTNcJq5irnfOiBk4Vq0D9r8uh9eRQCgZVTCX8fNDhGl0gLlcvOIhL9JTn6bj4KGh4MrYsEHRfI7XD-PZyDIDMliZlwesrw3D4wQaHEs3QYAYn7VpKkOXZ0uYOPcDEZKJZgfQx1bSCjEYOxrBp0-9N7Vb4iwUaDzXDQtYbzGdAfvaU9LuEci0l8PkXDjk2z28xVOEXR1biWMhci3FZoqY47CaSjHEeJStAVOm5mEWy76ype4aBJ6e1f1JNr5xvOPdQMLeGzlg.QAK60NWaZVLHOWGd.MAPO8dBIwdnCxQLPeHvPBhMISbxHcLlmX6SsUyznnTA_rL9oaX-lbwUaMnJG8JEsOQhXEpRDL8R8wGqSf_euZUFPxjMVtuJXhlnYBulNju-Ce20nq72xPq5TsPsvUUjwms_Z9VRcJiyq9t88KU-SbWY4D7A8zlIj_QYu7UE7jwP-5rJ9ZJ_9BiLQ4nxoueQARTs8IbOy-W38YU8gCpXJqkIc9FIA5sEiQE2YTppisXrUajeffARk7-0wGQTxodWTOoMSEQBVnBtYr0AglnzYOl89PmDjNhf_5ViJJV_AxbKCrTXjd_akDVkhPDAad6qtJFGJVNNdXfnd2Q3UwKGp2vTp52xY6q66t3aELZKHIM861Qry0tQZaagBXJDg2JKZCOG6ylj0a3ZVtKyworBLdbj6tvrS6lJ1LqivaahCCyXAGoWq203VR55l9k7BPW325AUTto8eUQ2qOGSB3h-nQF9rnbKdIp5VQj4o0ub7QARuhoZ7cyfLPWEs013xQnuXwdLTFAN4dV42WxTo6ZWAMwFWRSRllRRhBHCtWd1XU-y0P6rZ1AvuJDGvX5YlSwcVnkmczueEcIxlucOmwRo9JkkZ31Lck6WKVnLx_yS-7zXKOcMNdPR5dEWZGENFLiRqns3q4654zygPt9N0WZbVcPZmyVqO0EYiVor_wfij9HUyZzjVb4YiYCNAKM_QJb1c0P6xYgiCqxSaWw-BUqYPrUZXEimxo9XWrIpWBBBNXtCMZqrTNKFXmOODQT-sDLVDj4C1X1bbtgr6D02G7gzvy2lpE3u4yB7PdL4peltuP0dvGqgg19oUw3JaJK-n-mzNXy5w_gwDr2YCcZc9lpvLqZX5QnIsk6_WIhgRBC5T5jurefnj_rvTQCEdCC2hDQxFhsXOlPMXbrYzQ7MpmxnN1JJFa5W3hzMhG8SXTNdlvI9IuqF1tDA_NY6AGUkzegmdiyARa-GXq3ZsWW9idfLYYWxc5yHfiDJzjqBBRlQZKjwNopfbOiFoNe_7KfB98Kt7cf2s41eM6LeSPtynyw.yN7-uTC9ihTAVuQLA5rJUg";

    String jwe_private_key_pem =
            "-----BEGIN PRIVATE KEY-----\n"
                    + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCZ92bxCHSFfY1V\n"
                    + "f7RPsj6sdvUhFsgOBjPMSuFxmpIk9L5+ps7dKpuoVgID5rfT6GT3l/ze3RQ16orp\n"
                    + "Oy0+iwuVCTFJlFs/L3i2dmWfvVyyiwOWp+9/MMvIVNUT7wDKGJLC9onoqAhnKEqI\n"
                    + "ERv080cD5NUns7BoUNytuEgWK+J3fRCsHGfeu+Vdl3C0hIE0grOerpWTYAZQQf3H\n"
                    + "vX/Q7PeGbDCKS+/1eOSBqJ67YiqSn66Qs4g/A89GzMMKuGZ6Lh33x/1kGvT5P8fk\n"
                    + "FzbqTJWPwN+tu9npw06MFM70/rabztNg1I6uMK/s/H85NjO4DB6SzrVcQu2mhNRG\n"
                    + "AncNuYLNAgMBAAECggEAAhUlpQYM6fxWQOphUm8a3FSrJB68J2yXR9IfBYAdrf+c\n"
                    + "I2Y0LbdEk8nzT+Q+G4s1tvcEUN+wc5dubItvwk2/UZwDVgvAKQmGUxfe2LcM5Q5d\n"
                    + "RsQ1/QFswsd4QEkpT9KBreGqmxya7zhHdaB8WJ5kE1DuVgBB7mbuJw3cAiA4s5n/\n"
                    + "QxyY3w0Lh89CTJx8IqlNihbjzY/OBanEK8IJe03twdGuGp4fiBnkPMvIzcBhdeXP\n"
                    + "+8a4NR//KaNvLGC+FcONLEtR0T2/bkjvUrMyBY2gngxYgSCldVXguuU5jGhezkmu\n"
                    + "+7gP0ipSwyRdR8G36twrpCv5fGruRoGdKqCr+viecQKBgQDINf+NGQpeoFf82UjU\n"
                    + "b27xz/4YP1td1iIyfNtTdBodC7h6o7Ce/+QNt2b0rVltXtXQ8Ci3uorBih9bMirX\n"
                    + "F6MBOj4cgdhKySDMaaex5zFr4LOYCJ2nK18sa7QobvkfN3htUcimD3/B6yiEHbpI\n"
                    + "9Tf71Ix0HOYKL1k7/JsM4TaYHQKBgQDE3o/LmeUM95PJCFAWbB+ZKM3A3x8klZ6m\n"
                    + "mntSzAFB8yLjXtN0Y34E6+tyXJvW20AE4EWdvjduC/JaxF51sBulnaZbZwDU4Q2G\n"
                    + "lJkXx7l/iHUaHedxQDvGzhtiiStd7kzh5XLckC8dvsR306z/035fic35VQhTAANv\n"
                    + "1vzFGx92cQKBgGgzWm7YMoJvV3v8pqAR4x8tjmSWTPo4oZG/U/NKQPEPEZOasCkA\n"
                    + "q3PMGWSM+DcpHYViCP8esmrqdUlkgdFytt7DrmHt3mGF7nEVKDc6SYmI6E/fZBYG\n"
                    + "R8F5yMkmgLgTibTz1MdA19BYkLy6MCMapWmHBRbFl6CDZiEHZrc8W8qtAoGBAMQi\n"
                    + "7GYvO8lQe3dFBe1g6ZZA1cS7Rp6/ReG8dPNHdlVLM84NMmR5nxquJNO6OjS0GTMC\n"
                    + "cbk3wqer1Vfi3i0oOFMnHo9frq9oTH5xW5kajc/mlqxfcK8fDK8DtrrT6FXbzdMd\n"
                    + "MvNV3usmnTy4slnqTrRGaeRneDShBcuOCCUj4ZOxAoGBAMGlZqGPjaMZKA4Ub/1y\n"
                    + "T9wwy40H2DjBfkvOd0+GGYNZkpPlMf6+OR4eaXIhR94g/jDB5rNWMOi3G54J/qsa\n"
                    + "4iqeWVRpP8kmb3NBJ/Wu0n6JaE2oMOygaMQdpSggPDU6kh9o2Q6Xm8Kc4XP4vR9f\n"
                    + "cQuZkb1AlVAWiCUHSL8mpDFC\n"
                    + "-----END PRIVATE KEY-----";

    String jwe_public_key_pem =
            "-----BEGIN PUBLIC KEY-----\n"
                    + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmfdm8Qh0hX2NVX+0T7I+\n"
                    + "rHb1IRbIDgYzzErhcZqSJPS+fqbO3SqbqFYCA+a30+hk95f83t0UNeqK6TstPosL\n"
                    + "lQkxSZRbPy94tnZln71csosDlqfvfzDLyFTVE+8AyhiSwvaJ6KgIZyhKiBEb9PNH\n"
                    + "A+TVJ7OwaFDcrbhIFivid30QrBxn3rvlXZdwtISBNIKznq6Vk2AGUEH9x71/0Oz3\n"
                    + "hmwwikvv9Xjkgaieu2Iqkp+ukLOIPwPPRszDCrhmei4d98f9ZBr0+T/H5Bc26kyV\n"
                    + "j8DfrbvZ6cNOjBTO9P62m87TYNSOrjCv7Px/OTYzuAweks61XELtpoTURgJ3DbmC\n"
                    + "zQIDAQAB\n"
                    + "-----END PUBLIC KEY-----";

    @BeforeEach
    void setUp() {
        j = new JWT();
    }

    @Test
    @DisplayName("Testing default values")
    void testDefaultValues() {
        JWT j = new JWT();
        assertEquals("", j.raw);
        assertEquals("", j.signature);
        assertEquals("", j.header);
        assertEquals("", j.payload);
    }

    @Test
    @DisplayName("Testing jwt decode and encode")
    void testJWTParse_build() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.parse(raw_jwt);

            String out = j.build();
            assertEquals(raw_jwt, out);
            String[] splitted = out.split("\\.");

            assertEquals(3, splitted.length);

            assertEquals(raw_header, splitted[0]);
            assertEquals(raw_payload, splitted[1]);
            assertEquals(raw_signature, splitted[2]);

            // assertEquals(raw_header, j.header);
            // assertEquals(raw_payload, j.payload);
            // assertEquals(raw_signature, j.signature);
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    @DisplayName("Testing jwt signing and verify")
    void testJWTSign_and_verify() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.parse(raw_jwt);
            j.sign = true;
            j.private_key_pem = private_pem_rsa;

            String out = j.build();
            assertNotEquals(raw_jwt, out);
            String[] splitted = out.split("\\.");

            assertEquals(3, splitted.length);

            assertEquals(raw_header, splitted[0]);
            assertEquals(raw_payload, splitted[1]);
            assertNotEquals(raw_signature, splitted[2]);

            JWT j2 = new JWT();
            j2.parse(out);
            j2.public_key_pem = public_pem_rsa;
            assertTrue(j2.check_sig());
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    @DisplayName("Testing jwt decode and encode")
    void test_jwt_wrong_signature() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.parse(raw_jwt);
            j.public_key_pem = public_pem_rsa;
            assertFalse(j.check_sig());
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    @DisplayName("Testing jwt decode and encode")
    void test_decrypt_encrypt_jwe() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.decrypt = true;
            j.private_key_pem_enc = jwe_private_key_pem;
            j.public_key_pem_enc = jwe_public_key_pem;
            j.parse(raw_jwe);

            String parsed_head = j.header;
            String parsed_payload = j.payload;
            String parsed_signature = j.signature;

            String out = j.build();

            JWT j2 = new JWT();
            j2.decrypt = true;
            j2.private_key_pem_enc = jwe_private_key_pem;
            j2.public_key_pem_enc = jwe_public_key_pem;
            j2.parse(out);

            assertEquals(parsed_head, j2.header);
            assertEquals(parsed_payload, j2.payload);
            assertEquals(parsed_signature, j2.signature);
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    void test_check_key() throws JOSEException {

        JWK senderJWK = JWK.parseFromPEMEncodedObjects(private_pem_rsa);
        JWK recipientPublicJWK = JWK.parseFromPEMEncodedObjects(jwe_public_key_pem);

        // Create JWT
        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID(senderJWK.getKeyID())
                                .build(),
                        new JWTClaimsSet.Builder()
                                .subject("alice")
                                .issueTime(new Date())
                                .issuer("https://c2id.com")
                                .build());

        // Sign the JWT
        signedJWT.sign(new RSASSASigner(senderJWK.toRSAKey()));

        // Create JWE object with signed JWT as payload
        JWEObject jweObject =
                new JWEObject(
                        new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                .contentType("JWT") // required to indicate nested JWT
                                .build(),
                        new Payload(signedJWT));

        // Encrypt with the recipient's public key
        jweObject.encrypt(new RSAEncrypter(recipientPublicJWK.toRSAKey()));

        // Serialise to JWE compact form
        String jweString = jweObject.serialize();
        System.out.println(jweString);
    }

    /**
     * @Test void test_complete() throws NoSuchAlgorithmException, ParsingException { String
     * public_pem = "-----BEGIN PUBLIC
     * KEY-----\nMCowBQYDK2VwAyEAPq3ZL01cG1DHZ4iZLiRlRJIlupb5MGfHipSBq1hG2Jo=\n-----END PUBLIC
     * KEY-----\n"; String private_pem = "-----BEGIN PRIVATE
     * KEY-----\nMC4CAQAwBQYDK2VwBCIEIFlqmiu8kHunEywNZhbZjdZcT1YGTUCoOlh9aHF+43UE\n-----END PRIVATE
     * KEY-----\n";
     *
     * <p>//KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
     * //keyGen.initialize(2048); //KeyPair pair = keyGen.generateKeyPair(); //PrivateKey sk =
     * pair.getPrivate(); //PublicKey pk = pair.getPublic();
     *
     * <p>String jws = Jwts.builder() .setSubject("Bob") .signWith(sk) .compact();
     *
     * <p>assertFalse(jws.equals(""));
     *
     * <p>JWT j = new JWT(); j.check_sig = true; j.public_key = "pk_string"; j.parse(raw_jwt);
     * } @Test @DisplayName("Testing jwt remove claim") void testJWTRemoveClaim() { boolean errors =
     * false; try { JWT j = new JWT(); j.parse(raw_jwt); j.removeClaim(Utils.Jwt_section.HEADER,
     * "typ"); String out = j.build();
     * assertEquals("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
     * out);
     *
     * <p>j = new JWT(); j.parse(raw_jwt); j.removeClaim(Utils.Jwt_section.PAYLOAD, "name"); out =
     * j.build();
     * assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
     * out);
     *
     * <p>String[] splitted = out.split("\\.");
     *
     * <p>} catch (ParsingException e) { errors = true; } assertFalse(errors);
     * } @Test @DisplayName("Testing jwt edit claim") void testJWTEditClaim() { boolean errors =
     * false; try { JWT j = new JWT(); j.parse(raw_jwt); j.editAddClaim(Utils.Jwt_section.HEADER,
     * "typ", "asdasd"); String out = j.build();
     * assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6ImFzZGFzZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
     * out);
     *
     * <p>j = new JWT(); j.parse(raw_jwt); j.editAddClaim(Utils.Jwt_section.PAYLOAD, "name",
     * "peppe"); out = j.build();
     * assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBlcHBlIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
     * out);
     *
     * <p>j = new JWT(); j.parse(raw_jwt); j.editAddClaim(Utils.Jwt_section.SIGNATURE, "", "peppe");
     * out = j.build();
     * assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.peppe",
     * out);
     *
     * <p>j = new JWT(); j.parse(raw_jwt); j.editAddClaim(Utils.Jwt_section.HEADER, "prova",
     * "provona"); out = j.build();
     * assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInByb3ZhIjoicHJvdm9uYSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
     * out);
     *
     * <p>j = new JWT(); j.parse(raw_jwt); j.editAddClaim(Utils.Jwt_section.PAYLOAD, "prova",
     * "provona"); out = j.build();
     * assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwicHJvdmEiOiJwcm92b25hIn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
     * out); } catch (ParsingException e) { errors = true; } assertFalse(errors);
     * } @Test @DisplayName("Claims edit") void test_claimEdit() { String in =
     * "eyJhbGciOiJSUzI1NiIsImtpZCI6IllodUlKVTZvMTVFVUN5cUEwTEhFcUpkLXhWUEpnb3lXNXdaMW80cGFkV3MifQ.eyJzY29wZSI6Im9wZW5pZCIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWx5aW5nLXBhcnR5Lm9yZzo4MDAxL29pZGMvcnAvY2FsbGJhY2siLCJyZXNwb25zZV90eXBlIjoiY29kZSIsIm5vbmNlIjoidUNhQkJ6RDNPa3VPbEVVenZUSGJOcWFoOHVZdTRVa3UiLCJzdGF0ZSI6IjZFY3JwdzlYNThZaFVXMVlYSHF4bEVEVUhvbXczNUlxIiwiY2xpZW50X2lkIjoiaHR0cDovL3JlbHlpbmctcGFydHkub3JnOjgwMDEvIiwiZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvYXV0aG9yaXphdGlvbiIsImFjcl92YWx1ZXMiOiJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDIiLCJpYXQiOjE2NTM5ODM4NTksImF1ZCI6WyJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvIiwiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL2F1dGhvcml6YXRpb24iXSwiY2xhaW1zIjp7ImlkX3Rva2VuIjp7ImZhbWlseV9uYW1lIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImVtYWlsIjp7ImVzc2VudGlhbCI6dHJ1ZX19LCJ1c2VyaW5mbyI6eyJnaXZlbl9uYW1lIjpudWxsLCJmYW1pbHlfbmFtZSI6bnVsbCwiZW1haWwiOm51bGwsImZpc2NhbF9udW1iZXIiOm51bGx9fSwicHJvbXB0IjoiY29uc2VudCBsb2dpbiIsImNvZGVfY2hhbGxlbmdlIjoiU2hOX0t0U3ZhMEtwS1pZUFZ2MEhVd0lFM1lHclhZeHBuVS1Vb1BGTEluZyIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJpc3MiOiJodHRwOi8vcmVseWluZy1wYXJ0eS5vcmc6ODAwMS8iLCJzdWIiOiJodHRwOi8vcmVseWluZy1wYXJ0eS5vcmc6ODAwMS8ifQ.mETftfWL9MYrf3BVnahWOilFYItkBSaTw3nhKu0UzfiAI5lFy1orNGatNIR-Dg4hgsFCXgaY9rJSi2TVRSqIsHAJPe0HC5sKfXJ-mka0_w4koGDjbmYRZVN3yI05QWsLpENlsuCk2JEgZfz5BvAuX_MgxytIQHhUgy7DsdoJW-6Bk2DPDUiG_bDrBBjdFYgVocaQrxW49NmVIwtVz3dbhdslGA6g0uX7Dp9lQ9HqyWr1YnHtxUdyfuM2wdwPf11fhZNI8Nu_tpgVUxUMQgyEFA1nAscos2FuvLhpNovuciyh0BAlrYTpbXpZ-hjBv5rbfIrv5wytRNhlK2VxP7DA2g";
     * boolean errors = false; try { j = new JWT(); j.parse(in);
     *
     * <p>boolean a = j.jwt.getBody().containsKey("family_name"); String s = (String)
     * j.jwt.getBody().get("family_name"); if (!a) { Object c = j.jwt.getBody().get("claims"); } }
     * catch (ParsingException e) { errors = true; } assertFalse(errors);
     * } @Test @DisplayName("Decode raw jwt") void test_decodeRawJwt() { String in =
     * "eyJhbGciOiJSUzI1NiIsImtpZCI6IllodUlKVTZvMTVFVUN5cUEwTEhFcUpkLXhWUEpnb3lXNXdaMW80cGFkV3MifQ.eyJzY29wZSI6Im9wZW5pZCIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWx5aW5nLXBhcnR5Lm9yZzo4MDAxL29pZGMvcnAvY2FsbGJhY2siLCJyZXNwb25zZV90eXBlIjoiY29kZSIsIm5vbmNlIjoiOUZKcWczZDBBS0FYTWpEcDRVRnpkbGJUdG5kazgxanUiLCJzdGF0ZSI6ImhURHVRS0t1YUY4dnVxRk1XSVN4NWlxaTBlOXlmRGJiIiwiY2xpZW50X2lkIjoiaHR0cDovL3JlbHlpbmctcGFydHkub3JnOjgwMDEvIiwiZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvYXV0aG9yaXphdGlvbiIsImFjcl92YWx1ZXMiOiJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDIiLCJpYXQiOjE2NTY0MDMxNzEsImF1ZCI6WyJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvIiwiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL2F1dGhvcml6YXRpb24iXSwiY2xhaW1zIjp7ImlkX3Rva2VuIjp7ImZhbWlseV9uYW1lIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImVtYWlsIjp7ImVzc2VudGlhbCI6dHJ1ZX19LCJ1c2VyaW5mbyI6eyJnaXZlbl9uYW1lIjpudWxsLCJmYW1pbHlfbmFtZSI6bnVsbCwiZW1haWwiOm51bGwsImZpc2NhbF9udW1iZXIiOm51bGx9fSwicHJvbXB0IjoiY29uc2VudCBsb2dpbiIsImNvZGVfY2hhbGxlbmdlIjoiLXJQSkJfNDFPaUVzUmtXSTNQeDJmNkdaVjdpdWNOQkVReTZXVzRaenVTOCIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJpc3MiOiJodHRwOi8vcmVseWluZy1wYXJ0eS5vcmc6ODAwMS8ifQ.hZQdNZoZeLNJrIezuXQIV0C5a9ZOubiYTOUYdtmbsR4F_NFZFKDZccbjYk-ntYa2O7_DgcwQ083kAv5dutwU6nhiHBh3K__W4zct2yxcsLspE2pvBbmMjvq7IqmEYgIR2NEBwtCz9RrV6srnjzygm3XHb7kpfu-Z2eVPzxRTqi1C5l-ZX-xPDr2YFFdpHVB17G3lXTEj_Mm6zr6uNeJkS8Ytscq6SXyni3OTj_bRLTLONjoypLRO-qw8z2d8lY7bYgx9mZCAuUtgS75yRlrHuGu4zsE3Bg3UigfnCO_Pqouq-HZOGEZ_7_Hra0S5V8BPek_fRhRH6K534rFWlApRMQ";
     *
     * <p>String out = JWT.decode_raw_jwt(in);
     *
     * <p>assertEquals("{" + "\"alg\":\"RS256\"," +
     * "\"kid\":\"YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs\"" +
     * "}.{\"scope\":\"openid\",\"redirect_uri\":\"http://relying-party.org:8001/oidc/rp/callback\",\"response_type\":\"code\",\"nonce\":\"9FJqg3d0AKAXMjDp4UFzdlbTtndk81ju\",\"state\":\"hTDuQKKuaF8vuqFMWISx5iqi0e9yfDbb\",\"client_id\":\"http://relying-party.org:8001/\",\"endpoint\":\"http://cie-provider.org:8002/oidc/op/authorization\",\"acr_values\":\"https://www.spid.gov.it/SpidL2\",\"iat\":1656403171,\"aud\":[\"http://cie-provider.org:8002/oidc/op/\",\"http://cie-provider.org:8002/oidc/op/authorization\"],\"claims\":{\"id_token\":{\"family_name\":{\"essential\":true},\"email\":{\"essential\":true}},\"userinfo\":{\"given_name\":null,\"family_name\":null,\"email\":null,\"fiscal_number\":null}},\"prompt\":\"consent
     * login\",\"code_challenge\":\"-rPJB_41OiEsRkWI3Px2f6GZV7iucNBEQy6WW4ZzuS8\",\"code_challenge_method\":\"S256\",\"iss\":\"http://relying-party.org:8001/\"}"
     * +
     * ".hZQdNZoZeLNJrIezuXQIV0C5a9ZOubiYTOUYdtmbsR4F_NFZFKDZccbjYk-ntYa2O7_DgcwQ083kAv5dutwU6nhiHBh3K__W4zct2yxcsLspE2pvBbmMjvq7IqmEYgIR2NEBwtCz9RrV6srnjzygm3XHb7kpfu-Z2eVPzxRTqi1C5l-ZX-xPDr2YFFdpHVB17G3lXTEj_Mm6zr6uNeJkS8Ytscq6SXyni3OTj_bRLTLONjoypLRO-qw8z2d8lY7bYgx9mZCAuUtgS75yRlrHuGu4zsE3Bg3UigfnCO_Pqouq-HZOGEZ_7_Hra0S5V8BPek_fRhRH6K534rFWlApRMQ",
     * out); }
     */
    @Test
    @DisplayName("Testing jwt decode and encode")
    void test_jwt_parse_change_order() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.parse(raw_jwt);

            j.header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}"; // invert header keys

            String out = j.build();
            assertEquals(raw_jwt, out);
            String[] splitted = out.split("\\.");

            assertEquals(3, splitted.length);

            assertEquals(raw_header, splitted[0]);
            assertEquals(raw_payload, splitted[1]);
            assertEquals(raw_signature, splitted[2]);

            // assertEquals(raw_header, j.header);
            // assertEquals(raw_payload, j.payload);
            // assertEquals(raw_signature, j.signature);
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    void test_jwt_with_string_escaped() throws ParsingException {
        JWT j = new JWT();
        String input_jwt =
                "eyJraWQiOiJjbGllbiIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwOlwvXC9hYWMtcHJvdmlkZXIub3JnOjgwODBcL2F1dGhcL29wZW5pZGZlZFwvbWV0YWRhdGFcLzcwZTYyYzNiLTgwMDYtNDdjYy1hMTg2LWVhMzdiZGEwMDRhOSIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoieEc2NEExa3ZzNC1CM29XRXpidlVUclRUanE0RHNoOTVsMDlYckotbG1sRSIsImNsaWVudF9pZCI6Imh0dHA6XC9cL2FhYy1wcm92aWRlci5vcmc6ODA4MFwvYXV0aFwvb3BlbmlkZmVkXC9tZXRhZGF0YVwvNzBlNjJjM2ItODAwNi00N2NjLWExODYtZWEzN2JkYTAwNGE5IiwiYXVkIjoiaHR0cDpcL1wvdHJ1c3QtYW5jaG9yLm9yZzo4MDAwXC9vaWRjXC9vcCIsInNjb3BlIjoib3BlbmlkIG9mZmxpbmVfYWNjZXNzIiwiYWNyX3ZhbHVlcyI6Imh0dHBzOlwvXC93d3cuc3BpZC5nb3YuaXRcL1NwaWRMMSIsImNsYWltcyI6eyJ1c2VyaW5mbyI6eyJodHRwczpcL1wvYXR0cmlidXRlcy5laWQuZ292Lml0XC9maXNjYWxfbnVtYmVyIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImh0dHBzOlwvXC9hdHRyaWJ1dGVzLmVpZC5nb3YuaXRcL2VfZGVsaXZlcnlfc2VydmljZSI6eyJlc3NlbnRpYWwiOnRydWV9LCJkb2N1bWVudF9kZXRhaWxzIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImRhdGVfb2ZfaXNzdWFuY2UiOnsiZXNzZW50aWFsIjp0cnVlfSwiYmlydGhkYXRlIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImVtYWlsX3ZlcmlmaWVkIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImFkZHJlc3MiOnsiZXNzZW50aWFsIjp0cnVlfSwiZ2VuZGVyIjp7ImVzc2VudGlhbCI6dHJ1ZX0sInBob25lX251bWJlcl92ZXJpZmllZCI6eyJlc3NlbnRpYWwiOnRydWV9LCJnaXZlbl9uYW1lIjp7ImVzc2VudGlhbCI6dHJ1ZX0sInBsYWNlX29mX2JpcnRoIjp7ImVzc2VudGlhbCI6dHJ1ZX0sInBob25lX251bWJlciI6eyJlc3NlbnRpYWwiOnRydWV9LCJmYW1pbHlfbmFtZSI6eyJlc3NlbnRpYWwiOnRydWV9LCJlbWFpbCI6eyJlc3NlbnRpYWwiOnRydWV9LCJ1c2VybmFtZSI6eyJlc3NlbnRpYWwiOnRydWV9fX0sInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2FhYy1wcm92aWRlci5vcmc6ODA4MFwvYXV0aFwvb3BlbmlkZmVkXC9sb2dpblwvNzBlNjJjM2ItODAwNi00N2NjLWExODYtZWEzN2JkYTAwNGE5Iiwic3RhdGUiOiIzd0o1cDV5U1lEVkwzWXptMVlRcWw1RDlzdWoxYS1LTlU1WEJHWXpYcmpBPSIsImV4cCI6MTcwNDg5ODY1MiwiaWF0IjoxNzA0ODk4MzUyLCJwcm9tcHQiOiJjb25zZW50IiwianRpIjoiZWExZGE0MmQtMmM0OC00ZjlhLWJiNzAtMzVkODJmY2Q2ZjU0IiwiY29kZV9jaGFsbGVuZ2UiOiJyVUcyalNpMDc2NnlQX044ai13ZUVDUmZPbWcyZ1NjZ1lNS20xS2JvMUpnIn0.ZVJDsU5xi0qUDPcUPV9Gi9u54DPp2HGLzwgPbAdZA6IX3Thnu3sBhTBSJts0L8RBfe4xXxlTOrkOL-OM7bWG4ZxITwIixFRVhsjRgF6QgPYmis3Nv464KgK_LePlmlXmRNNC6cGTxwiAD_PLPyb2Earcp23FWNaQe5XGfil2gbVQimtSAlHjl3zUCnndAWGQbgtb6jXGdxzEDZlOdZH_WNxgFqpSHZmS-BCfc4yLukZS43iGDBYHpbTv2J4mMg5RFYBPMcS09zBtFuI6lmZcayczMpsdZfnCre44zi19xPtf2y4vSnf_I66k8AudumAGmLJFazzfGhp8MCy3nomstA";

        j.parse(input_jwt);
        String built_jwt = j.build();

        assertEquals(input_jwt, built_jwt);
    }
}
