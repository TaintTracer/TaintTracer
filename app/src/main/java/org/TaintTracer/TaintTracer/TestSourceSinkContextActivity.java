package org.TaintTracer.TaintTracer;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.provider.ContactsContract;
import android.system.Os;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class TestSourceSinkContextActivity extends AppCompatActivity implements View.OnClickListener, LocationListener{
    private static String TAG = "SourceSinkActivity";
    static final boolean bgThread = true;
    private InetSocketAddress endpoint = new InetSocketAddress("192.168.1.59", 11211);

    static {
        System.loadLibrary("source-sink");
    }

    native String nativeSource();

    native void nativeSink(final String s);

    native void runRegressionTests();

    native void runNativeOverheadBenchmark();

    native void runNewNativeOverheadBenchmark();

    native void runNewNativeOverheadBenchmarkParameterized(int iterations, int taintedRegisters);

    /**
     * Get tainted data and send it to a sink in native code with 1 step
     */
    native void nativeSourceToNativeSink();

    native void markByteArrayAsTainted(byte[] array, int offset, int size);

    native void markIntArrayAsTainted(int[] array, int offset, int size);

    native void markLongArrayAsTainted(long[] array, int offset, int size);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.getFilesDir();
        setContentView(R.layout.activity_test_source_sink_context);

        findViewById(R.id.java_to_java).setOnClickListener(this);
        findViewById(R.id.java_to_native).setOnClickListener(this);
        findViewById(R.id.native_to_java).setOnClickListener(this);
        findViewById(R.id.native_to_native).setOnClickListener(this);
        findViewById(R.id.java_benchmark_legacy).setOnClickListener(this);
        findViewById(R.id.test).setOnClickListener(this);
        findViewById(R.id.native_overhead_benchmark).setOnClickListener(this);
        findViewById(R.id.java_overhead_benchmark).setOnClickListener(this);
        findViewById(R.id.new_native_overhead_benchmark).setOnClickListener(this);
        findViewById(R.id.new_java_overhead_benchmark).setOnClickListener(this);
        findViewById(R.id.automated_overhead_benchmark).setOnClickListener(this);
        findViewById(R.id.process_gps).setOnClickListener(this);

        if (!bgThread) {
            StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
            StrictMode.setThreadPolicy(policy);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    String javaSource() {
        Cursor cursor = getContentResolver().query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null, "has_phone_number > 0", null, null);
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
    void legacyBenchmark() {
        TextView t = findViewById(R.id.java_benchmark_time);
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
        t.setText("Benchmark time: " + benchmark_time_ms + " ms, " + (stop_time - start_time) + " ns (Res: " + res + ")");
    }

    long input[] = new long[] {52, 8121, 15, 548, 2154, 293, 41586, 1452, 4586, 12545};
    int iterationInstructions = 0; // Used by evaluation/overhead/count_ins_java.sh
    long javaOverheadBenchmarkIteration() {
        long max_len = 1;
        long dp[] = new long[10];

        for (int i = 0; i < dp.length; i++) {
            dp[i] = 1;
        }

        for (int i = 0; i < 10; i++) {
            for (int j = i + 1; j < 10; j++) {
                if (input[i] < input[j]) {
                    long lis_i = dp[i] + 1;
                    long lis_j = dp[j];
                    dp[j] = lis_j < lis_i ? lis_i : lis_j;
                    max_len = max_len < dp[j] ? dp[j] : max_len;
                }
            }
        }
        return max_len;
    }

    /*
     * Number of bytecode instructions of javaOverheadBenchmark:
     * 3 // Stack and argument setup, epilogue and return
     * + (iterations - 1) * (6 + 803) // All but the last iteration
     * + (3 + 803) // Last iteration
     * + taint_iters * (instructions that process tainted data)
     * = iterations * (6 + 803) + taint_iters * 11
     */
    void javaOverheadBenchmark(byte[] buffer, long iterations, long taint_iterations) {
        // Rewrite of overhead_benchmark in source-sink-lib.cpp
        long i = 1;
        while(true) {
            javaOverheadBenchmarkIteration();
            i++;
            if (i == iterations) break;
            if (i > taint_iterations) continue;
            // Process tainted data
            byte b = buffer[0];
            b += 1;
            b <<= 3;
            b -= 7;
            b >>= 1;
            buffer[0] = b;
        }
        /*
        .method javaOverheadBenchmark([BJJ)V
            .locals 6

            const-wide/16 v0, 0x1

            move-wide v2, v0

            :goto_0
            invoke-virtual {p0}, Lorg/TaintTracer/TaintTracer/TestSourceSinkContextActivity;->javaOverheadBenchmarkIteration()J

            add-long/2addr v2, v0

            cmp-long v4, v2, p2

            if-nez v4, :cond_0

            return-void

            :cond_0
            cmp-long v4, v2, p4

            if-lez v4, :cond_1

            goto :goto_0

            :cond_1
            const/4 v4, 0x0

            aget-byte v5, p1, v4

            add-int/lit8 v5, v5, 0x1

            int-to-byte v5, v5

            shl-int/lit8 v5, v5, 0x3

            int-to-byte v5, v5

            add-int/lit8 v5, v5, -0x7

            int-to-byte v5, v5

            shr-int/lit8 v5, v5, 0x1

            int-to-byte v5, v5

            aput-byte v5, p1, v4

            goto :goto_0
        .end method

         */
    }

    void runJavaOverheadBenchmark() {
        // Sufficiently large such that GetByteArrayElements' isCopy is false
        byte taintedData[] = new byte[12 * 1024];
        markByteArrayAsTainted(taintedData, 0, taintedData.length);

        int samples = 10;
        int iterations = 100_000;

        int[] taintIterations = new int[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        for (int t_it : taintIterations) {
            long benchmarkTimes[] = new long[samples];
            for (int i = 0; i < samples; i++) {
                long start = System.nanoTime();
                javaOverheadBenchmark(taintedData, iterations, t_it);
                long stop = System.nanoTime();
                long time = stop - start;
                Log.i(TAG, String.format("Java benchmark time (%d taint iters): %d ns", t_it, time));
                benchmarkTimes[i] = time;
            }

            double sum = 0.0;
            for (long t : benchmarkTimes) {
                sum += t;
            }
            double mean = sum / (double)benchmarkTimes.length;
            double stddev = 0.0;
            for (long t : benchmarkTimes) {
                stddev += Math.pow(t - mean, 2);
            }
            stddev = Math.sqrt(stddev) / (double)benchmarkTimes.length;
            Log.i(TAG, String.format("Average java benchmark time (%d taint iters): %f ns (stddev: %f ns)", t_it, mean, stddev));
        }
        if (iterationInstructions > 0) {
            Log.i(TAG, String.format("Number of bytecode instructions of benchmark iteration: %d", iterationInstructions));
        } else {
            Log.d(TAG, "iterationInstructions has not been updated. Smali is not instrumented or benchmark iteration hasn't been executed at least once.");
        }
    }

    /*
     * Total number of executed bytecode instructions:
     * 26 + 23 * iterations + 1 + 51
     * With 100 iterations: 2378
     */
    void newJavaOverheadBenchmark(int[] buffer, int offset, int iterations) {
        int var0 = buffer[offset + 0];
        int var1 = buffer[offset + 1];
        int var2 = buffer[offset + 2];
        int var3 = buffer[offset + 3];
        int var4 = buffer[offset + 4];
        int var5 = buffer[offset + 5];
        int var6 = buffer[offset + 6];
        int var7 = buffer[offset + 7];
        int var8 = buffer[offset + 8];
        int var9 = buffer[offset + 9];

        for (int i = 0; i < iterations; i++) {
            var0++;
            var0 >>= 3;
            var1++;
            var1 >>= 3;
            var2++;
            var2 >>= 3;
            var3++;
            var3 >>= 3;
            var4++;
            var4 >>= 3;
            var5++;
            var5 >>= 3;
            var6++;
            var6 >>= 3;
            var7++;
            var7 >>= 3;
            var8++;
            var8 >>= 3;
            var9++;
            var9 >>= 3;
        }

        // TODO: find faster variable sink to avoid removal of unused variables
        buffer[offset + 0] = var0;
        buffer[offset + 1] = var1;
        buffer[offset + 2] = var2;
        buffer[offset + 3] = var3;
        buffer[offset + 4] = var4;
        buffer[offset + 5] = var5;
        buffer[offset + 6] = var6;
        buffer[offset + 7] = var7;
        buffer[offset + 8] = var8;
        buffer[offset + 9] = var9;

        var0 = buffer[offset + 10];
        var1 = buffer[offset + 11];
        var2 = buffer[offset + 12];
        var3 = buffer[offset + 13];
        var4 = buffer[offset + 14];
        var5 = buffer[offset + 15];
        var6 = buffer[offset + 16];
        var7 = buffer[offset + 17];
        var8 = buffer[offset + 18];
        var9 = buffer[offset + 19];

        var0++;
        var1++;
        var2++;
        var3++;
        var4++;
        var5++;
        var6++;
        var7++;
        var8++;
        var9++;

        buffer[offset + 10] = var0;
        buffer[offset + 11] = var1;
        buffer[offset + 12] = var2;
        buffer[offset + 13] = var3;
        buffer[offset + 14] = var4;
        buffer[offset + 15] = var5;
        buffer[offset + 16] = var6;
        buffer[offset + 17] = var7;
        buffer[offset + 18] = var8;
        buffer[offset + 19] = var9;
    }

    void runNewJavaOverheadBenchmark() {
        int iterations = 100;
        int samples = 1;

        int taintedData[] = new int[4 * 1024];
        markIntArrayAsTainted(taintedData, 0, 2 * 1024);
        for (int tainted_variables = 0; tainted_variables <= 10; tainted_variables++) {
            long benchmarkTimes[] = new long[samples];
            int offset = 2 * 1024 - tainted_variables;
            for (int i = 0; i < samples; i++) {
                long start = System.nanoTime();
                newJavaOverheadBenchmark(taintedData, offset, iterations);
                long stop = System.nanoTime();
                long time = stop - start;
                benchmarkTimes[i] = time;
                Log.i(TAG, String.format("New java benchmark time (%d tainted regs): %d ns", tainted_variables, time));
            }

            double sum = 0.0;
            for (long t : benchmarkTimes) {
                sum += t;
            }
            double mean = sum / (double)benchmarkTimes.length;
            double stddev = 0.0;
            for (long t : benchmarkTimes) {
                stddev += Math.pow(t - mean, 2);
            }
            stddev = Math.sqrt(stddev) / (double)benchmarkTimes.length;
            Log.i(TAG, String.format("Average new java benchmark time (%d tainted regs): %f ns (stddev: %f ns)", tainted_variables, mean, stddev));
        }
    }

    void automatedOverheadBenchmark() {
        // Read which benchmark to run with what parameters
        FileInputStream benchmarkCommandIS = null;
        try {
            benchmarkCommandIS = this.openFileInput("bench.command");
        } catch (FileNotFoundException e) {
            Log.e(TAG, "No bench.command file found. Exiting...");
            e.printStackTrace();
            System.exit(1);
        }

        BufferedReader commandReader = new BufferedReader(new InputStreamReader(benchmarkCommandIS));

        String environment = null;
        int taintedRegisters = -1;
        try {
            environment = commandReader.readLine();
            taintedRegisters = Integer.parseInt(commandReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
        assert(0 <= taintedRegisters && taintedRegisters <= 10);

        int iterations = 100;
        if (environment.equals("java")) {
            int taintedData[] = new int[4 * 1024];
            markIntArrayAsTainted(taintedData, 0x3fd, 1024);
            int offset = 0x3fd + 1024 - taintedRegisters;
            long start = System.nanoTime();
            newJavaOverheadBenchmark(taintedData, offset, iterations);
            long stop = System.nanoTime();
            long time = stop - start;
            Log.i(TAG, String.format("New java benchmark time (%d tainted regs): %d ns", taintedRegisters, time));
        } else {
            runNewNativeOverheadBenchmarkParameterized(iterations, taintedRegisters);
        }
    }

    void processLocation() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED && ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[] { Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION }, 0);
            return;
        }

        LocationManager locationManager = (LocationManager) getSystemService(LOCATION_SERVICE);
        boolean synchronous = false;
        if (synchronous) {
            while (true) {
                try {
                    Thread.sleep(3_000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                Location l = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                Os.getegid();
            }
        } else {
            locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0, this);
        }
    }

    @Override
    public void onLocationChanged(@NonNull Location location) {
        Os.getegid();
        System.err.println("onLocationChanged called");
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
            case R.id.java_benchmark_legacy:
                legacyBenchmark();
                break;
            case R.id.test:
                runRegressionTests();
                break;
            case R.id.native_overhead_benchmark:
                runNativeOverheadBenchmark();
                break;
            case R.id.java_overhead_benchmark:
                runJavaOverheadBenchmark();
                break;
            case R.id.new_native_overhead_benchmark:
                runNewNativeOverheadBenchmark();
                break;
            case R.id.new_java_overhead_benchmark:
                runNewJavaOverheadBenchmark();
                break;
            case R.id.automated_overhead_benchmark:
                automatedOverheadBenchmark();
                break;
            case R.id.process_gps:
                processLocation();
                break;
            default:
                System.err.println("Unsupported view sent an onClick event");
        }
    }
}
