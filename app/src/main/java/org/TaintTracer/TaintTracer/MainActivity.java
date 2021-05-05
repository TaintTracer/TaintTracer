package org.TaintTracer.TaintTracer;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.system.Os;
import android.util.Log;
import android.os.Build;

import java.io.FileInputStream;

public class MainActivity extends AppCompatActivity {
    private static String TAG = "NTMainActivity";

    static {
        // Using external launcher to initiate taint tracking for now
        // System.loadLibrary("native-lib");
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (grantResults.length == 0) return;
        if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            Intent i = new Intent(this, TestSourceSinkContextActivity.class);
            startActivity(i);
        } else {
            Log.e(TAG, "perm not granted");
            throw new RuntimeException("Contact permission has not been granted");
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        requestPermissions(new String[]{Manifest.permission.READ_CONTACTS}, 1);
    }
}
