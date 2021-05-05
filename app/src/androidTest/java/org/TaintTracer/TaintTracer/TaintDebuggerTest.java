package org.TaintTracer.TaintTracer;

import android.content.Context;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class TaintDebuggerTest {
    /**
     * Run the native test runner on the target device.
     * Detailed output is redirected to Logcat.
     */
    @Test
    public void runNativeTestRunner() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        String nativeLibraryDir = appContext.getApplicationInfo().nativeLibraryDir;
        String testRunnerPath = nativeLibraryDir + "/tainttracer-test.so";
        System.out.println("Starting native test runner: " + testRunnerPath);
        try {
            Process p = new ProcessBuilder()
                    .redirectErrorStream(true)
                    .command(testRunnerPath)
                    .directory(appContext.getDataDir())
                    .start();
            InputStream is = p.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line;
            while ((line = br.readLine()) != null)
            {
                Log.d("TaintDebuggerTest", line);
            }
            assertEquals(0, p.waitFor());
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute native test runner: " + e.getMessage());
        }
    }
}
