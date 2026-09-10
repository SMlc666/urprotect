package com.example.urprotect;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private static final String TAG = "UrProtectFixture";

    static {
        System.loadLibrary("fixture");
    }

    private static native String fixtureValue();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String value = fixtureValue();
        Log.i(TAG, "URPROTECT_FIXTURE_RESULT=" + value);
        TextView textView = new TextView(this);
        textView.setText(value);
        setContentView(textView);
    }
}
