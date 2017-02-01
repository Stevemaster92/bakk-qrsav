package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.activities;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;

import java.security.Provider;
import java.security.Security;
import java.util.Set;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.R;

public class MainActivity extends AppCompatActivity {
    public static final String EXTRA_SPECS_ALGORITHM_FOR_KEYS = "EXTRA_SPECS_ALGORITHM_FOR_KEYS";
    public static final String EXTRA_SPECS_ALGORITHM_FOR_SIGN = "EXTRA_SPECS_ALGORITHM_FOR_SIGN";
    public static final String EXTRA_SPECS_PROVIDER = "EXTRA_SPECS_ALGORITHM_FOR_PROVIDER";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(String.format(getString(R.string.title_activity_main), getString(R.string.app_name)));

        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar_main);
        setSupportActionBar(toolbar);

        //listSupportedSecurityProviders();
    }

    /**
     * Starts the QR code scanner activity.
     */
    public void openScanner(View v) {
        startActivity(createIntent(QRCodeScannerActivity.class));
    }

    /**
     * Starts the QR code generator activity.
     */
    public void openGenerator(View v) {
        startActivity(createIntent(QRCodeGeneratorActivity.class));
    }

    /**
    * Creates an intent with cryptographically extras for a specific class.
    */
    private Intent createIntent(Class<?> cls) {
        Intent intent = new Intent(this, cls);
        // Initialize specifications with ECDSA.
        intent.putExtra(EXTRA_SPECS_ALGORITHM_FOR_KEYS, "EC");
        intent.putExtra(EXTRA_SPECS_ALGORITHM_FOR_SIGN, "SHA256withECDSA");
        // Bouncy Castle is the specific security provider supported by Android.
        intent.putExtra(EXTRA_SPECS_PROVIDER, "BC");

        return intent;
    }

    /**
     * ONLY IN USE FOR TESTING.
     * Lists all security providers supported by the android platform.
     */
    private void listSupportedSecurityProviders() {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Log.i("CRYPTO", "provider: " + provider.getName());
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                Log.i("CRYPTO", "  algorithm: " + service.getAlgorithm());
            }
        }
    }
}
