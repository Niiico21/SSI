import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EmpaquetarFactura {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Uso: EmpaquetarFactura <fichero JSON factura> <nombre paquete> <clave pública Hacienda>");
            return;
        }

        String jsonFacturaPath = args[0];
        String paquetePath = args[1];
        String clavePublicaHaciendaPath = args[2];

        // Leer la factura (fichero JSON)
        byte[] facturaBytes = Files.readAllBytes(Paths.get(jsonFacturaPath));

        // Leer la clave pública de Hacienda
        PublicKey clavePublicaHacienda = leerClavePublica(clavePublicaHaciendaPath);

        // Generar clave simétrica (AES) para cifrar la factura
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey claveSimetrica = keyGen.generateKey();

        // Cifrar la factura con AES (clave simétrica)
        Cipher cipherAES = Cipher.getInstance("AES");
        cipherAES.init(Cipher.ENCRYPT_MODE, claveSimetrica);
        byte[] facturaCifrada = cipherAES.doFinal(facturaBytes);

        // Cifrar la clave simétrica con la clave pública de Hacienda (RSA)
        Cipher cipherRSA = Cipher.getInstance("RSA");
        cipherRSA.init(Cipher.ENCRYPT_MODE, clavePublicaHacienda);
        byte[] claveSimetricaCifrada = cipherRSA.doFinal(claveSimetrica.getEncoded());

        // Guardar paquete con factura cifrada y clave simétrica cifrada
        Paquete paquete = new Paquete();
        paquete.anadirBloque("facturaCifrada", facturaCifrada);
        paquete.anadirBloque("claveSimetricaCifrada", claveSimetricaCifrada);
        paquete.escribirPaquete(paquetePath);

        System.out.println("Factura empaquetada correctamente en: " + paquetePath);
    }

    private static PublicKey leerClavePublica(String clavePublicaPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(clavePublicaPath));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(spec);
    }
}
