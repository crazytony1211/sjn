# MiniAppHost-Android-Java — Safe postMessage bridge version

This version updates the bridge to use a **safe `postMessage` communication** channel between the mini app’s JavaScript and the Android host (instead of `addJavascriptInterface`). This avoids the reflection-based security risks of direct JS interfaces.

---

## Key changes
- Replaced `addJavascriptInterface` with a custom `WebChromeClient` that intercepts `window.postMessage()` calls using a JS `console.log` trick.
- The bridge listens for JSON messages and dispatches them safely.
- Mini apps send messages via `window.postMessage(JSON.stringify({ action: 'showToast', data: 'Hi!' }))`.

---

## Updated files

### MiniAppWebViewActivity.java
```java
package com.example.miniapphost;

import android.os.Bundle;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.util.Log;
import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;

import org.json.JSONObject;

public class MiniAppWebViewActivity extends AppCompatActivity {
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_webview);

        webView = findViewById(R.id.webview);

        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);

        webView.setWebViewClient(new WebViewClient());

        // Set up a custom ChromeClient to capture postMessage logs
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onConsoleMessage(android.webkit.ConsoleMessage cm) {
                String msg = cm.message();
                if (msg.startsWith("MINIAPP:")) {
                    handleMessage(msg.substring(8));
                    return true;
                }
                return super.onConsoleMessage(cm);
            }
        });

        Intent intent = getIntent();
        String url = intent.getStringExtra("url");
        if (url != null) {
            webView.loadUrl(url);
        } else {
            webView.loadUrl("file:///android_asset/miniapps/shop/index.html");
        }
    }

    private void handleMessage(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            String action = obj.optString("action");
            String data = obj.optString("data");

            if ("showToast".equals(action)) {
                MiniAppBridge.showToast(this, data);
            }
        } catch (Exception e) {
            Log.e("MiniApp", "Invalid message: " + json, e);
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
```

---

### MiniAppBridge.java
```java
package com.example.miniapphost;

import android.content.Context;
import android.widget.Toast;

public class MiniAppBridge {
    public static void showToast(Context context, String message) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
    }
}
```

---

### assets/miniapps/shop/js/app.js
```javascript
function postToHost(obj) {
  console.log('MINIAPP:' + JSON.stringify(obj));
}

function sayHello() {
  postToHost({ action: 'showToast', data: 'Hello safely from Mini App!' });
}

// Example: ask platform info
postToHost({ action: 'getPlatform' });
```

---

## Why this is safer
- **No reflection**: `addJavascriptInterface` uses Java reflection, which attackers could abuse on old Android versions (<17). This pattern avoids that.
- **Controlled parsing**: All messages must start with `MINIAPP:` and be valid JSON.
- **One-way communication**: Native code can validate and decide what to execute.

---

If you’d like, I can now add **two-way messaging** (so the host can call back into JS using `evaluateJavascript()`), or extend it with a simple **API permission check system** for mini apps.

