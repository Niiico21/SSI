import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SellarFactura {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Uso: SellarFactura <nombre paquete> <clave privada autoridad> <clave pública empresa>");
            return;
        }

        String paquetePath = args[0];
        String clavePrivadaAutoridadPath = args[1];
        String clavePublicaEmpresaPath = args[2];

        // Leer el paquete
        Paquete paquete = Paquete.leerPaquete(paquetePath);

        // Leer la clave privada de la Autoridad
        PrivateKey clavePrivadaAutoridad = leerClavePrivada(clavePrivadaAutoridadPath);

        // Leer la clave pública de la Empresa
        PublicKey clavePublicaEmpresa = leerClavePublica(clavePublicaEmpresaPath);

        // Generar sello de tiempo
        String selloTiempo = String.valueOf(System.currentTimeMillis());
        paquete.anadirBloque("selloTiempo", selloTiempo.getBytes());

        // Firmar el paquete con la clave privada de la Autoridad
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(clavePrivadaAutoridad);
        signature.update(paquete.getContenidoBloque("facturaCifrada"));
        byte[] firma = signature.sign();
        paquete.anadirBloque("firmaAutoridad", firma);

        // Guardar el paquete actualizado
        paquete.escribirPaquete(paquetePath);

        System.out.println("Factura sellada y firmada correctamente.");
    }

    private static PrivateKey leerClavePrivada(String clavePrivadaPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(clavePrivadaPath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private static PublicKey leerClavePublica(String clavePublicaPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(clavePublicaPath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}
