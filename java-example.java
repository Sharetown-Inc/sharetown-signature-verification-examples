import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class SharetownSignatureVerificationExample {
    static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    static final String BASE64_ENCODED_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAku0+XYKYnxehSKwzRzPwE/M20nYbd7DF5SxFF2UxUxWSxJYlwTV9DkDUXOC61YuVhNEnMWBqZ7SGh8eCO65Np4U7kgrdbpG3yIZM1UMun74ZVEIrzqyaw+S7kNCPS9xPL1Y5vCn0tXWkGB02vWBAvXRQebBXj90cDC0Umg1ChE1hpZ1CCU4DcvkPvqg6ge0WgLwAuHPJaxyKK7/uz6AkUeYKsRp6ZiayuK65nyRuIFGhoq6c1SErYWvv3ir70pKoIRevNJTEB8yGCp4OnclTv/w36y5uAV0ORa3NcKXLBdyzMTb2bIEtQ7qTuHqPdCljWJwc+IdLqVFKdvLtEs792wIDAQAB";
    static final String BASE64_ENCODED_SIGNATURE = "cxwLTcDP96fpaWamDavtQ+isgXUFxoxDTonz+98mG1YQPmOO+dpwE73V3zu9GpelJR51qhs/CoTHUIDYzwVs3JWWJCdg3sKCPDYbH5k8EWT2/k2FRzabrjeNuBcA04bwNYmFqr4AbPo3FQ+06bOPqtuXEHF8EXng9Zj56aLaM0HmkGpAcH16zCNJRR0JIWBFXAMq35pdJOR/VApfGKwNPhS3kNaUucCnDpcowdENmO8S+i8vKUxYRD3iYO/LQYiUH8DDiFJQZXJN7jlgSD3yNUFFpLg40Pp1izoiqNj/10qvNTJAau2CuRa635Uge3LjHSOpidUQjk7WH6urBEUWZw==";
    static final String WEBHOOK_NOTIFICATION_URL = "https://webhook.site/df6b68ca-d447-47aa-a84e-60d440b74a85";
    static final String WEBHOOK_NOTIFICATION_PAYLOAD = "{\"webhook_id\":\"dc95d60d-3626-459e-927e-844c0f301356\",\"webhook_notification_id\":\"8cefbe48-dace-4444-9287-9106575629a2\",\"pickup_request_id\":\"2e5d4b71-cbcb-4017-ba49-0bb14a4616e0\",\"external_id\":\"UCE9381474\",\"pickup_time\":\"2022-01-13T12:04:22.758118\",\"event_time\":\"2022-01-13T19:04:52.758456Z\",\"event\":\"pickup-completed\"}";

    public static void main(String[] args) {
        Base64.Decoder decoder = Base64.getDecoder();

        try {
            KeySpec keySpec = new X509EncodedKeySpec(decoder.decode(BASE64_ENCODED_PUBLIC_KEY));
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

            Signature sign = Signature.getInstance(SIGNATURE_ALGORITHM);
            sign.initVerify(publicKey);
            sign.update((WEBHOOK_NOTIFICATION_URL + WEBHOOK_NOTIFICATION_PAYLOAD).getBytes());

            boolean result = sign.verify(decoder.decode(BASE64_ENCODED_SIGNATURE));
            System.out.println("Valid: " + result);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
