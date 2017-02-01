package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.activities;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.drawable.BitmapDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.support.v4.view.MenuItemCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.ShareActionProvider;
import android.support.v7.widget.Toolbar;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.FileHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.R;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.SignatureEntity;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.exceptions.NoSignatureSpecHolderException;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler.SignatureHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.KeyPairFactory;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

public class QRCodeGeneratorActivity extends AppCompatActivity {
    private static final String SIGN_MESSAGE_TAG = "Signing message";
    private static final String ENCODE_MESSAGE_TAG = "Encoding message";
    private static final String SAVE_IMAGE_TAG = "Saving image";
    private static final String DELETE_IMAGE_TAG = "Deleting image";

    private SignatureSpecHolder holder;
    private FileHandler fh;
    private boolean signing, saved;
    private ShareActionProvider shareActionProvider;
    private Intent shareIntent;
    private Uri uriToImage;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(String.format(getString(R.string.title_activity_qrcode_generator), getString(R.string.app_name)));
        setContentView(R.layout.activity_qrcode_generator);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar_generator);
        setSupportActionBar(toolbar);

        // Initialize share intent.
        shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType("image/jpeg");

        holder = SignatureSpecHolder.getInstance();
        // Get specifications from MainActivity's intent.
        holder.setSpecs(getIntent().getStringExtra(MainActivity.EXTRA_SPECS_ALGORITHM_FOR_KEYS),
                getIntent().getStringExtra(MainActivity.EXTRA_SPECS_ALGORITHM_FOR_SIGN),
                getIntent().getStringExtra(MainActivity.EXTRA_SPECS_PROVIDER));

        // Create a file handler and directories on the internal storage.
        try {
            fh = FileHandler.getInstance(getApplicationContext(), holder);
        } catch (IOException e) {
            Log.e(FileHandler.CREATE_TAG, e.getMessage());
        }

        signing = true;
        saved = false;
        uriToImage = null;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_qrcode_generator, menu);

        shareActionProvider = (ShareActionProvider) MenuItemCompat.getActionProvider(menu.findItem(R.id.action_sharing));

        return true;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        // Delete old temporarily stored QR code image.
        if (uriToImage != null)
            deleteTempImage();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.action_saving:
                if (!saved) {
                    if (saveQRCodeAsImage() != null) {
                        Toast.makeText(this, R.string.saving_success, Toast.LENGTH_SHORT).show();
                        saved = true;
                    } else
                        Toast.makeText(this, R.string.saving_failed, Toast.LENGTH_SHORT).show();
                } else
                    Toast.makeText(this, R.string.saving_saved, Toast.LENGTH_SHORT).show();
                return true;
            case R.id.action_signing:
                item.setChecked(!item.isChecked());
                if (item.isChecked()) {
                    signing = true;
                    Toast.makeText(this, R.string.signing_enabled, Toast.LENGTH_SHORT).show();
                } else {
                    signing = false;
                    Toast.makeText(this, R.string.signing_disabled, Toast.LENGTH_SHORT).show();
                }
                return true;
            default:
                break;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * Updates the share intent.
     */
    private void updateShareIntent() {
        if (shareActionProvider != null && uriToImage != null) {
            shareIntent.putExtra(Intent.EXTRA_STREAM, Uri.parse("file://" + uriToImage.getPath()));
            shareActionProvider.setShareIntent(shareIntent);
        }
    }

    /**
     * Generates a signed QR code from the input text.
     */
    public void generateQRCode(View v) {
        ImageView img = (ImageView) findViewById(R.id.img_qrcode);
        String text = ((EditText) findViewById(R.id.input_text)).getText().toString();

        // Empty message not allowed!
        if (text.equals("")) {
            Toast.makeText(this, R.string.encoding_empty_failed, Toast.LENGTH_SHORT).show();
            return;
        }

        Log.d("Gen Data QR Code", text);

        // Signing enabled.
        if (signing) {
            // Generate signature.
            SignatureEntity sig = null;
            try {
                sig = generateSignature(text.getBytes());
            } catch (NoSuchAlgorithmException | NoSuchProviderException |
                    NoSignatureSpecHolderException | SignatureException |
                    InvalidKeyException | InvalidKeySpecException |
                    InvalidAlgorithmParameterException | IOException e) {
                Log.e(SIGN_MESSAGE_TAG, e.getMessage());
            }

            if (sig == null) {
                Toast.makeText(this, R.string.signature_create_failed, Toast.LENGTH_SHORT).show();
                return;
            }

            // Append signature to input String.
            text = text.concat(sig.toString());
        }

        // Determine optimal size for QR code image.
        // Find screen size.
        DisplayMetrics metrics = new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getMetrics(metrics);
        int width = metrics.widthPixels;
        int height = metrics.heightPixels;
        // Find optimal size for QR code image.
        int minDisplayScale = width < height ? width : height;
        int minImageScale = img.getWidth() < img.getHeight() ? img.getWidth() : img.getHeight();
        int minScale = minDisplayScale < minImageScale ? minDisplayScale : minImageScale;

        // Encode input String and convert it to a Bitmap object.
        Log.d("Generate QR Code", "Content: " + text);
        Log.d("Generate QR Code", "Length: " + text.getBytes().length + " bytes");
        Bitmap bmp = encodeToBitmap(text, minScale);

        // Show generated QR code image.
        if (bmp != null) {
            img.setImageBitmap(bmp);
            // Delete old temporarily stored QR code image.
            if (uriToImage != null)
                deleteTempImage();

            // Store QR code image temporarily.
            uriToImage = saveQRCodeAsImage();
            // Update share intent.
            if (uriToImage != null) {
                updateShareIntent();
                saved = false;
            } else
                Log.e(SAVE_IMAGE_TAG, "QR code not saved temporarily");
        }
    }

    /**
     * Encodes the given String to a QR code by using ZXing's {@link QRCodeWriter} and transforms it to a {@link Bitmap}.
     *
     * @param text The String to encode.
     * @param size The size of the generated image.
     * @return The new {@link Bitmap}.
     */
    private Bitmap encodeToBitmap(String text, int size) {
        BitMatrix m = null;

        try {
            // Character encoding using UTF-8.
            Map<EncodeHintType, String> hints = new HashMap<>();
            hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
            m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints);
        } catch (WriterException | IllegalArgumentException e) {
            Log.e(ENCODE_MESSAGE_TAG, e.getMessage());

            if (e.getMessage().contains("Data too big"))
                Toast.makeText(this, R.string.encoding_too_big_failed, Toast.LENGTH_SHORT).show();
        }

        if (m == null)
            return null;

        int height = m.getHeight();
        int width = m.getWidth();
        Bitmap bmp = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565);
        int[] pixels = new int[width * height];

        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                pixels[y * width + x] = m.get(x, y) ? Color.BLACK : Color.WHITE;
            }
        }

        bmp.setPixels(pixels, 0, width, 0, 0, width, height);

        return bmp;
    }

    /**
     * Generates a signature for the specific data.
     *
     * @param data The data to be signed.
     * @return The new {@link SignatureEntity}.
     */
    private SignatureEntity generateSignature(byte[] data) throws NoSuchAlgorithmException,
            NoSuchProviderException, NoSignatureSpecHolderException, IOException,
            SignatureException, InvalidKeyException, InvalidKeySpecException,
            InvalidAlgorithmParameterException {
        // Either get the private key from its key file or generate a new key pair, store it
        // on storage if it does not exist and get the private key from them.
        PrivateKey key;
        if (fh.existsKeyPair())
            // Get private key by its file name.
            key = fh.getPrivateKey();
        else {
            // Generate new key pair and save them.
            KeyPairFactory factory = new KeyPairFactory(holder);
            KeyPair keys = factory.generate();
            fh.saveKeyPair(keys);
            // Get only private key for generating the signature.
            key = keys.getPrivate();
        }

        // Generate new signature.
        return (new SignatureHandler(holder)).sign(data, key);
    }

    private Uri saveQRCodeAsImage() {
        Uri uriToImage = null;
        ImageView img = (ImageView) findViewById(R.id.img_qrcode);

        try {
            Bitmap bmp = ((BitmapDrawable) img.getDrawable()).getBitmap();
            uriToImage = fh.saveQRCode(bmp);
            Log.d(SAVE_IMAGE_TAG, uriToImage.getPath());
        } catch (NullPointerException | IOException e) {
            Log.e(SAVE_IMAGE_TAG, e.getMessage());
        }

        return uriToImage;
    }

    private void deleteTempImage() {
        File file = new File(uriToImage.getPath());
        if (file.exists()) {
            boolean deleted = file.delete();

            if (deleted) {
                Log.d(DELETE_IMAGE_TAG, "'" + file.getAbsolutePath() + "' deleted");
                uriToImage = null;
            } else
                Log.d(DELETE_IMAGE_TAG, "'" + file.getAbsolutePath() + "' not deleted");
        }
    }
}
