package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav;

import android.content.Context;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Random;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

/**
 * Created by stefan on 12/3/15.
 */
public class FileHandler {
    private static final String READ_TAG = "Read file";
    private static final String WRITE_TAG = "Write file";
    public static final String CREATE_TAG = "Create directory";
    public static final String keyDir = "keys/";
    public static final String codeDir = "codes/";
    private static FileHandler instance = null;
    private SignatureSpecHolder holder;
    private Context context;

    public static FileHandler getInstance(Context context, SignatureSpecHolder holder) throws IOException {
        return instance == null ? new FileHandler(context, holder) : instance;
    }

    private FileHandler(Context context, SignatureSpecHolder holder) throws IOException {
        this.holder = holder;
        this.context = context;

        if (isExternalStorageAvailable())
            createDirectories();
        else
            throw new IOException("External storage not available.");
    }

    public PublicKey getPublicKey(String keyFileName) throws IOException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeySpecException {
        return (PublicKey) getKey(keyFileName, true);
    }

    public List<PublicKey> getPublicKeys() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        File file = new File(context.getExternalFilesDir(null) + "/" + keyDir);
        List<PublicKey> publicKeys = new ArrayList<>();

        if (!isDirEmpty(file)) {
            String suffix = "-" + holder.getAlgorithmForKeys().toLowerCase() + ".pub";

            // Iterate through key file names to get all public key files which end with the given suffix.
            // There could be more than one public key file!
            for (String fileName : file.list())
                if (fileName.endsWith(suffix))
                    // Get public key from public key file and add it to the list.
                    publicKeys.add(getPublicKey(fileName.split(suffix)[0]));
        }

        return publicKeys.isEmpty() ? null : publicKeys;
    }

    public PrivateKey getPrivateKey() throws IOException,
            NoSuchProviderException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        return (PrivateKey) getKey(getPrivateKeyFileName(), false);
    }

    private String getPrivateKeyFileName() throws IOException {
        File file = new File(context.getExternalFilesDir(null) + "/" + keyDir);

        if (!isDirEmpty(file)) {
            String[] fileNames = file.list();
            String suffix = "-" + holder.getAlgorithmForKeys().toLowerCase();

            // Iterate through key file names to get the private key file which ends with the given suffix.
            // There should be only one private key file!
            for (String fileName : fileNames)
                if (fileName.endsWith(suffix))
                    // Return prefix of key file name.
                    return fileName.split("-")[0];
        }

        return null;
    }

    private Key getKey(String keyFileName, boolean isPublicKey) throws IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String suffix = "-" + holder.getAlgorithmForKeys().toLowerCase();

        if (isPublicKey)
            suffix = suffix.concat(".pub");

        File file = new File(context.getExternalFilesDir(null) + "/" + keyDir, keyFileName.concat(suffix));
        byte[] data = readFile(file);
        byte[] encKey = Arrays.copyOf(data, data.length);
        KeyFactory keyFactory = KeyFactory.getInstance(holder.getAlgorithmForKeys(),
                holder.getProvider());

        KeySpec keySpec;
        // Return public key.
        if (isPublicKey) {
            keySpec = new X509EncodedKeySpec(encKey);
            return keyFactory.generatePublic(keySpec);
        }

        // Return private key.
        keySpec = new PKCS8EncodedKeySpec(encKey);
        return keyFactory.generatePrivate(keySpec);
    }

    public void saveKeyPair(KeyPair keys) throws IOException {
        String fileName = getRandomFileName();

        saveKey(keys.getPrivate(), fileName);
        saveKey(keys.getPublic(), fileName);
    }

    private void saveKey(Key key, String fileName) throws IOException {
        String suffix = "-" + holder.getAlgorithmForKeys().toLowerCase();

        if (key instanceof PublicKey)
            suffix = suffix.concat(".pub");

        File file = new File(context.getExternalFilesDir(null) + "/" + keyDir, fileName.concat(suffix));

        if (key instanceof PublicKey) {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key.getEncoded());
            writeFile(keySpec.getEncoded(), file);
        } else {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key.getEncoded());
            writeFile(keySpec.getEncoded(), file);
        }
    }

    public Uri saveQRCode(Bitmap bmp) throws IOException {
        String fileName = "qrcode_" + getRandomFileName();
        File file = new File(context.getExternalFilesDir(null) + "/" + codeDir, fileName.concat(".jpeg"));

        saveBitmap(bmp, file);

        return Uri.parse(file.getAbsolutePath());
    }

    private void saveBitmap(Bitmap bmp, File file) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        bmp.compress(Bitmap.CompressFormat.JPEG, 100, fos);
        fos.flush();
        fos.close();
    }

    public byte[] readFile(File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] buf = new byte[fis.available()];
        fis.read(buf);
        fis.close();
        Log.d(READ_TAG, file.getAbsolutePath());

        return Arrays.copyOf(buf, buf.length);
    }

    public void writeFile(byte[] buf, File file) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(buf);
        fos.close();
        Log.d(WRITE_TAG, file.getAbsolutePath());
    }

    public boolean existsKeyPair() throws IOException {
        File file = new File(context.getExternalFilesDir(null) + "/" + keyDir);

        // Check if key files exist.
        if (isDirEmpty(file)) return false;

        String[] fileNames = file.list();
        String pattern = "-" + holder.getAlgorithmForKeys().toLowerCase() + ".pub";

        // Find the one and only private key.
        for (String fileName : fileNames) {
            // Private key is that file which does not end with the given pattern.
            if (!fileName.endsWith(pattern)) {
                // Find the corresponding public key.
                for (String fn : fileNames)
                    // Corresponding public key is that file which ends with the given pattern
                    // and has the same file name as the private key.
                    if (fn.endsWith(pattern) && fileName.startsWith(fileName))
                        return true;
            }
        }

        return false;
    }

    private boolean createDirectories() throws IOException {
        boolean created = false;

        // This equals to
        //  - external storage: /storage/emulated/0/Android/data/at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav/files
        if (isDirEmpty(context.getExternalFilesDir(null))) {
            File f = new File(context.getExternalFilesDir(null), "keys");
            created = f.mkdirs();
            Log.d(CREATE_TAG, f.getAbsolutePath());

            if (created) {
                f = new File(context.getExternalFilesDir(null), "codes");
                created = f.mkdirs();
                Log.d(CREATE_TAG, f.getAbsolutePath());
            }
        }

        return created;
    }

    private boolean isDirEmpty(File file) throws IOException {
        if (file.isDirectory())
            return file.list().length <= 0;
        else
            throw new IOException("\'" + file.getAbsolutePath() + "\' is not a directory.");
    }

    private String getRandomFileName() {
        // Generate a hash value of the current timestamp and set it as key filename.
        int num = SimpleDateFormat.getDateTimeInstance().format(Calendar.getInstance().getTime()).hashCode();

        while (num <= 0) {
            num += BigInteger.probablePrime(256, new Random()).intValue();
        }

        return Integer.toString(num);
    }

    private boolean isExternalStorageAvailable() {
        return Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState());
    }
}
