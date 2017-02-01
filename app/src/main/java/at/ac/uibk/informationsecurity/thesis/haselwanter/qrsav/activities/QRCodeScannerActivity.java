package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.activities;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.hardware.Camera;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.StringDef;
import android.support.v4.view.MenuItemCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.ShareActionProvider;
import android.support.v7.widget.Toolbar;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.vision.CameraSource;
import com.google.android.gms.vision.barcode.Barcode;
import com.google.android.gms.vision.barcode.BarcodeDetector;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.DecodeHintType;
import com.google.zxing.FormatException;
import com.google.zxing.LuminanceSource;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.FileHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.R;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.SignatureEntity;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler.SignatureHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

public class QRCodeScannerActivity extends AppCompatActivity {
    private static final String VERIFY_MESSAGE_TAG = "Verifying message";
    private static final String DECODE_MESSAGE_TAG = "Decoding message";

    private CameraSource cam;
    private BarcodeDetector detector;
    private SurfaceHolder surfaceHolder;
    private TextView codeContent, verifyResult;
    private ShareActionProvider shareActionProvider;
    private Intent shareIntent;

    private SignatureSpecHolder specHolder;
    private FileHandler fh;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(String.format(getString(R.string.title_activity_qrcode_scanner), getString(R.string.app_name)));
        setContentView(R.layout.activity_qrcode_scanner);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar_scanner);
        setSupportActionBar(toolbar);

        codeContent = (EditText) findViewById(R.id.codeContent);
        verifyResult = (TextView) findViewById(R.id.verifyResult);

        // Initialize share intent.
        shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType("text/plain");

        SurfaceView cameraView = (SurfaceView) findViewById(R.id.camera_view);
        surfaceHolder = cameraView.getHolder();

        specHolder = SignatureSpecHolder.getInstance();
        // Get specifications from MainActivity's intent.
        specHolder.setSpecs(getIntent().getStringExtra(MainActivity.EXTRA_SPECS_ALGORITHM_FOR_KEYS),
                getIntent().getStringExtra(MainActivity.EXTRA_SPECS_ALGORITHM_FOR_SIGN),
                getIntent().getStringExtra(MainActivity.EXTRA_SPECS_PROVIDER));

        // Create a file handler and directories on the internal storage.
        try {
            fh = FileHandler.getInstance(getApplicationContext(), specHolder);
        } catch (IOException e) {
            Log.e(FileHandler.CREATE_TAG, e.getMessage());
        }

        // Open camera and preview.
        openCamera();
        initCameraView();
    }

    @Override
    protected void onPause() {
        super.onPause();
        releaseCamera();
    }

    @Override
    protected void onResume() {
        super.onResume();
        openCamera();
        initCameraView();
        startView();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        releaseCamera();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_qrcode_scanner, menu);

        shareActionProvider = (ShareActionProvider) MenuItemCompat.getActionProvider(menu.findItem(R.id.action_sharing));
        updateShareIntent();

        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        return super.onOptionsItemSelected(item);
    }

    /**
     * Updates the share intent.
     */
    private void updateShareIntent() {
        if (shareActionProvider != null) {
            shareIntent.putExtra(Intent.EXTRA_TEXT, codeContent.getText().toString());
            shareActionProvider.setShareIntent(shareIntent);
        }
    }

    /**
     * Scans a detected QR code, decodes it and verifies the message's signature.
     */
    public void scanQRCode(View v) {
        cam.takePicture(null, new CameraSource.PictureCallback() {
            @Override
            public void onPictureTaken(byte[] data) {
                // Try to decode QR code.
                String decString = decode(data);

                // No QR code detected.
                if (decString == null || decString.length() == 0) {
                    // Call setText method inside the post method of the TextView,
                    // otherwise it will not run on the UI thread.
                    // Failing to do so will lead to a runtime error.
                    codeContent.post(new Runnable() {
                        @Override
                        public void run() {
                            codeContent.setText("");
                            updateShareIntent();
                        }
                    });

                    verifyResult.post(new Runnable() {
                        @Override
                        public void run() {
                            verifyResult.setTextColor(getResources().getColor(
                                    R.color.colorPrimary));
                            verifyResult.setText(getResources().getString(R.string.verify_result_default));
                        }
                    });

                    return;
                }

                Log.d("Decoded string", decString);

                SignatureHandler sh = new SignatureHandler(specHolder);
                // Split decoded String into data part and signature part.
                final String[] dataSign = sh.getContent(decString);

                // QR code contains a signature.
                if (dataSign.length == 2) {
                    boolean verifies = false;

                    try {
                        // Get signature bytes in ISO-8859-1 format.
                        SignatureEntity sign = new SignatureEntity(
                                dataSign[1].getBytes("ISO-8859-1"));
                        // Get public keys.
                        List<PublicKey> pks = fh.getPublicKeys();

                        // No public key was found.
                        if (pks == null)
                            throw new InvalidKeyException("No public key found");

                        // Try all available public keys to verify signature.
                        for (PublicKey key : pks)
                            if (verifies = sh.verify(sign, dataSign[0].getBytes("UTF-8"), key))
                                break;
                    } catch (NoSuchAlgorithmException | NoSuchProviderException |
                            SignatureException | InvalidKeyException |
                            InvalidKeySpecException | IOException e) {
                        Log.e(VERIFY_MESSAGE_TAG, e.getMessage());
                    }

                    // Signature is valid.
                    if (verifies) {
                        // Call setText method inside the post method of the TextView,
                        // otherwise it will not run on the UI thread.
                        // Failing to do so will lead to a runtime error.
                        codeContent.post(new Runnable() {
                            @Override
                            public void run() {
                                codeContent.setText(dataSign[0]);
                                Log.d("Decoded text", "Content: " + dataSign[0]);
                                Log.d("Decoded text", "Length: " + dataSign[0].getBytes().length + " bytes");
                                updateShareIntent();
                            }
                        });

                        verifyResult.post(new Runnable() {
                            @Override
                            public void run() {
                                verifyResult.setTextColor(getResources().getColor(
                                        R.color.colorValid));
                                verifyResult.setText(getResources().getString(R.string.verify_result_success));
                            }
                        });
                    }
                    // Signature is invalid.
                    else {
                        // Call setText method inside the post method of the TextView,
                        // otherwise it will not run on the UI thread.
                        // Failing to do so will lead to a runtime error.
                        codeContent.post(new Runnable() {
                            @Override
                            public void run() {
                                codeContent.setText("");
                                updateShareIntent();
                            }
                        });

                        verifyResult.post(new Runnable() {
                            @Override
                            public void run() {
                                verifyResult.setTextColor(getResources().getColor(
                                        R.color.colorInvalid));
                                verifyResult.setText(getResources().getString(R.string.verify_result_failed));
                            }
                        });
                    }
                }
                // QR code does not contain a signature.
                else {
                    // Call setText method inside the post method of the TextView,
                    // otherwise it will not run on the UI thread.
                    // Failing to do so will lead to a runtime error.
                    codeContent.post(new Runnable() {
                        @Override
                        public void run() {
                            codeContent.setText(dataSign[0]);
                            Log.d("Decoded text", "Content: " + dataSign[0]);
                            Log.d("Decoded text", "Length: " + dataSign[0].getBytes().length + " bytes");
                            updateShareIntent();
                        }
                    });

                    verifyResult.post(new Runnable() {
                        @Override
                        public void run() {
                            verifyResult.setTextColor(getResources().getColor(
                                    R.color.colorGray));
                            verifyResult.setText(getResources().getString(R.string.verify_result_no));
                        }
                    });
                }
            }
        });
    }

    /**
     * Decodes the given (QR code) data by transforming it to a {@link BinaryBitmap} first and then
     * giving it to the ZXing's {@link QRCodeReader} as input.
     *
     * @param data The data to be decoded.
     * @return The decoded QR code content.
     */
    private String decode(byte[] data) {
        Bitmap bmp = BitmapFactory.decodeByteArray(data, 0, data.length);
        int[] intData = new int[bmp.getWidth() * bmp.getHeight()];
        bmp.getPixels(intData, 0, bmp.getWidth(), 0, 0, bmp.getWidth(), bmp.getHeight());

        LuminanceSource src = new RGBLuminanceSource(bmp.getWidth(), bmp.getHeight(), intData);
        BinaryBitmap bbmp = new BinaryBitmap(new HybridBinarizer(src));

        Result r = null;
        try {
            // Character decoding using ISO-8859-1.
            Map<DecodeHintType, String> hints = new HashMap<>();
            hints.put(DecodeHintType.CHARACTER_SET, "UTF-8");
            r = new QRCodeReader().decode(bbmp, hints);
        } catch (NotFoundException e) {
            Log.e(DECODE_MESSAGE_TAG, "No code found");
        } catch (ChecksumException e) {
            Log.e(DECODE_MESSAGE_TAG, "Checksum feature failed");
        } catch (FormatException e) {
            Log.e(DECODE_MESSAGE_TAG, "Wrong format");
        }

        return r == null ? null : r.getText();
    }

    /******************************************************************************************
     * CAMERA AND CAMERA VIEW INITIALIZATION
     *****************************************************************************************/
    private boolean checkCameraHardware(Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA);
    }

    private void initCameraView() {
        surfaceHolder.addCallback(new SurfaceHolder.Callback() {
            @Override
            public void surfaceCreated(SurfaceHolder holder) {
                startView();
            }

            @Override
            public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
                refreshCamera();
            }

            @Override
            public void surfaceDestroyed(SurfaceHolder holder) {
                releaseCamera();
            }
        });
    }

    private void startView() {
        try {
            cam.start(surfaceHolder);
        } catch (IOException e) {
            Log.e("CAMERA", "Failed to open camera");
        }

        // Set focus mode.
        if (!cameraFocus(cam, Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE))
            Toast.makeText(getApplicationContext(), getString(R.string.auto_focus_failed),
                    Toast.LENGTH_SHORT).show();
    }

    private void openCamera() {
        // Check if device has a camera.
        if (checkCameraHardware(this)) {
            if (cam == null) {
                // Init barcode detector.
                // Detector currently not in use but is needed for capturing!
                // Images will be captured using CameraSource.takePicture(), otherwise detector
                // throws exception due to smileys and other symbols could not be captured.
                detector = new BarcodeDetector.Builder(this).setBarcodeFormats(
                        Barcode.QR_CODE).build();
                // Init camera.
                DisplayMetrics metrics = new DisplayMetrics();
                ((WindowManager) getSystemService(WINDOW_SERVICE)).getDefaultDisplay()
                        .getMetrics(metrics);
                cam = new CameraSource.Builder(this, detector).setRequestedPreviewSize(
                        metrics.widthPixels, metrics.heightPixels).build();
            }
        }
    }

    private void refreshCamera() {
        if (surfaceHolder.getSurface() == null) {
            return;
        }

        cam.stop();
        // TODO Insert changes here.
        startView();
    }

    private void releaseCamera() {
        if (cam != null) {
            detector.release();
            cam.stop();
            cam.release();        // release the camera for other applications
            cam = null;
        }
    }

    /******************************************************************************************
     * VISION API FOCUS FIX
     * from https://gist.github.com/Gericop/7de0b9fdd7a444e53b5a
     * This fixes the auto focus option in CameraSource, because its not available in the
     * PlayServices yet.
     * *****************************************************************************************/
    /* IF YOU WANT TO JUST ACCESS THE CAMERA INSTANCE SO THAT YOU CAN SET ANY OF THE PARAMETERS,
     * VISIT THE FOLLOWING LINK:
     * https://gist.github.com/Gericop/364dd12b105fdc28a0b6
     */

    /**
     * <p>
     * Sets the Mobile Vision API provided {@link com.google.android.gms.vision.CameraSource}'s
     * focus mode. Use {@link Camera.Parameters#FOCUS_MODE_CONTINUOUS_PICTURE} or
     * {@link Camera.Parameters#FOCUS_MODE_CONTINUOUS_VIDEO} for continuous autofocus.
     * </p>
     * <p>
     * Note that the CameraSource's {@link CameraSource#start()} or
     * {@link CameraSource#start(SurfaceHolder)} has to be called and the camera image has to be
     * showing prior using this method as the CameraSource only creates the camera after calling
     * one of those methods and the camera is not available immediately. You could implement some
     * kind of a callback method for the SurfaceHolder that notifies you when the imaging is ready
     * or use a direct action (e.g. button press) to set the focus mode.
     * </p>
     * <p>
     * Check out <a href="https://github.com/googlesamples/android-vision/blob/master/face/multi-tracker/app/src/main/java/com/google/android/gms/samples/vision/face/multitracker/ui/camera/CameraSourcePreview.java#L84">CameraSourcePreview.java</a>
     * which contains the method <code>startIfReady()</code> that has the following line:
     * <blockquote><code>mCameraSource.start(mSurfaceView.getHolder());</code></blockquote><br>
     * After this call you can use our <code>cameraFocus(...)</code> method because the camera is ready.
     * </p>
     *
     * @param cameraSource The CameraSource built with {@link com.google.android.gms.vision.CameraSource.Builder}.
     * @param focusMode    The focus mode. See {@link android.hardware.Camera.Parameters} for possible values.
     * @return true if the camera's focus is set; false otherwise.
     * @see com.google.android.gms.vision.CameraSource
     * @see android.hardware.Camera.Parameters
     */
    public boolean cameraFocus(@NonNull CameraSource cameraSource, @FocusMode @NonNull String focusMode) {
        Field[] declaredFields = CameraSource.class.getDeclaredFields();

        for (Field field : declaredFields) {
            if (field.getType() == Camera.class) {
                field.setAccessible(true);
                try {
                    Camera camera = (Camera) field.get(cameraSource);
                    if (camera != null) {
                        Camera.Parameters params = camera.getParameters();

                        if (!params.getSupportedFocusModes().contains(focusMode)) {
                            return false;
                        }

                        params.setFocusMode(focusMode);
                        camera.setParameters(params);
                        return true;
                    }

                    return false;
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }

                break;
            }
        }

        return false;
    }

    /**
     * Custom annotation to allow only valid focus modes.
     */
    @StringDef({
            Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE,
            Camera.Parameters.FOCUS_MODE_CONTINUOUS_VIDEO,
            Camera.Parameters.FOCUS_MODE_AUTO,
            Camera.Parameters.FOCUS_MODE_EDOF,
            Camera.Parameters.FOCUS_MODE_FIXED,
            Camera.Parameters.FOCUS_MODE_INFINITY,
            Camera.Parameters.FOCUS_MODE_MACRO
    })

    @Retention(RetentionPolicy.SOURCE)
    private @interface FocusMode {
    }

}


