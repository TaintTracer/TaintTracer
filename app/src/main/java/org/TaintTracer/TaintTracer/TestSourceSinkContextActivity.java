package org.TaintTracer.TaintTracer;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.database.Cursor;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.provider.ContactsContract;
import android.view.View;
import android.widget.TextView;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class TestSourceSinkContextActivity extends AppCompatActivity implements View.OnClickListener {
    private static String TAG = "NTMainActivity";
    static final boolean bgThread = true;
    private InetSocketAddress endpoint = new InetSocketAddress("192.168.1.77", 11211);

    static {
        System.loadLibrary("source-sink");
    }

    native String nativeSource();
    native void nativeSink(final String s);
    native void run_regression_tests();

    /**
     * Get tainted data and send it to a sink in native code with 1 step
     */
    native void nativeSourceToNativeSink();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_source_sink_context);

        findViewById(R.id.java_to_java).setOnClickListener(this);
        findViewById(R.id.java_to_native).setOnClickListener(this);
        findViewById(R.id.native_to_java).setOnClickListener(this);
        findViewById(R.id.native_to_native).setOnClickListener(this);
        findViewById(R.id.java_benchmark).setOnClickListener(this);
        findViewById(R.id.test).setOnClickListener(this);

        if (!bgThread) {
            StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
            StrictMode.setThreadPolicy(policy);
        }
    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    String javaSource() {
        Cursor cursor = getContentResolver().query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null, "has_phone_number > 0",null, null);
        assert cursor != null;
        if (cursor.moveToNext()) {
            String phoneNumber = cursor.getString(cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER));
            cursor.close();
            return phoneNumber;
        } else {
            throw new RuntimeException("No contacts in contact list");
        }
    }


    void javaSink(final String s) {
        if (bgThread) {
            try {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Socket socket = new Socket();
                        try {
                            socket.connect(endpoint);
                            OutputStream w = socket.getOutputStream();
                            w.write(s.getBytes());
                            w.flush();
                            socket.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                            System.exit(1);
                        }
                    }
                }).start();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            Socket socket = new Socket();
            try {
                socket.connect(endpoint);
                OutputStream w = socket.getOutputStream();
                w.write(s.getBytes());
                w.flush();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    @SuppressLint("SetTextI18n")
    void benchmark() {
        TextView t = findViewById(R.id.benchmark_time_result);
        t.setText("Running benchmark...");
        final long start_time = System.nanoTime();
        String x = javaSource();

        int res = 0;
        for (int i = 0; i < 10_000_000; i++) {
            int a = 1;
            int b = 1;
            final int N = 46;
            for (int n = 2; n < N; n++) {
                int tmp = b;
                b += a;
                a = tmp;
            }
            res = b;
        }

        javaSink(x);

        final long stop_time = System.nanoTime();
        final long benchmark_time = stop_time - start_time;
        final int benchmark_time_ms = (int) (benchmark_time / 1_000_000);
        t.setText("Benchmark time: " + benchmark_time_ms + " ms, " + (stop_time - start_time) + " ns (Res: " + res +")");
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.java_to_java:
                javaSink(javaSource());
                break;
            case R.id.java_to_native:
                nativeSink(javaSource());
                break;
            case R.id.native_to_java:
                javaSink(nativeSource());
                break;
            case R.id.native_to_native:
                nativeSourceToNativeSink();
                break;
            case R.id.java_benchmark:
                benchmark();
                break;
            case R.id.test:
                run_regression_tests();
            default:
                System.err.println("Unsupported view sent an onClick event");
        }
    }
}
