package com.example.security;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.crypto.Cipher;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import javax.security.auth.x500.X500Principal;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;

public class DeviceIntegrityChecker {

    private static final String TAG = "DeviceIntegrityChecker";
    private static final String OFFICIAL_SIGNATURE_HASH = "YOUR_RELEASE_SIGNATURE_HASH"; // Base64

    private final Context context;

    public DeviceIntegrityChecker(Context context) {
        this.context = context;
    }

    /** Main entry point — runs all checks */
    public IntegrityReport checkIntegrity() {
        IntegrityReport report = new IntegrityReport();
        report.isRooted = isRooted();
        report.isEmulator = isEmulator();
        report.isDebuggerAttached = android.os.Debug.isDebuggerConnected();
        report.isSignatureValid = isAppSignatureValid();
        report.isSelinuxEnforcing = checkSelinux();
        report.isVerifiedBootGreen = checkVerifiedBoot();
        report.isHardwareBackedKey = checkHardwareKeystore();

        report.isDeviceTrusted = !report.isRooted
                && !report.isEmulator
                && report.isSignatureValid
                && report.isSelinuxEnforcing
                && report.isVerifiedBootGreen
                && report.isHardwareBackedKey
                && !report.isDebuggerAttached;

        return report;
    }

    /** Root detection */
    private boolean isRooted() {
        String[] paths = {"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su"};
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        try {
            Process p = Runtime.getRuntime().exec("which su");
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            if (br.readLine() != null) return true;
        } catch (Exception ignored) {}
        return false;
    }

    /** Emulator detection */
    private boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.MODEL.contains("google_sdk")
                || Build.MANUFACTURER.contains("Genymotion")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk".equals(Build.PRODUCT);
    }

    /** App signature validation */
    private boolean isAppSignatureValid() {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            for (Signature signature : packageInfo.signatures) {
                String currentHash = Base64.encodeToString(signature.toByteArray(), Base64.NO_WRAP);
                if (currentHash.equals(OFFICIAL_SIGNATURE_HASH)) return true;
            }
        } catch (Exception e) {
            Log.e(TAG, "Signature check failed", e);
        }
        return false;
    }

    /** SELinux enforcing */
    private boolean checkSelinux() {
        String output = exec("getenforce");
        return output != null && output.trim().equalsIgnoreCase("Enforcing");
    }

    /** Verified boot status */
    private boolean checkVerifiedBoot() {
        String output = exec("getprop ro.boot.verifiedbootstate");
        return output != null && output.trim().equalsIgnoreCase("green");
    }

    /** Hardware-backed key test */
    private boolean checkHardwareKeystore() {
        try {
            String alias = "IntegrityKey";
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(alias,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setUserAuthenticationRequired(false)
                            .setIsStrongBoxBacked(true)
                            .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            KeyFactory factory = KeyFactory.getInstance(keyPair.getPrivate().getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = factory.getKeySpec(keyPair.getPrivate(), KeyInfo.class);
            return keyInfo.isInsideSecureHardware();
        } catch (Exception e) {
            Log.e(TAG, "Keystore integrity check failed", e);
            return false;
        }
    }

    /** Run shell command helper */
    private String exec(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            return br.readLine();
        } catch (Exception e) {
            return null;
        }
    }

    /** Report object */
    public static class IntegrityReport {
        public boolean isRooted;
        public boolean isEmulator;
        public boolean isDebuggerAttached;
        public boolean isSignatureValid;
        public boolean isSelinuxEnforcing;
        public boolean isVerifiedBootGreen;
        public boolean isHardwareBackedKey;
        public boolean isDeviceTrusted;

        @Override
        public String toString() {
            return "IntegrityReport{" +
                    "rooted=" + isRooted +
                    ", emulator=" + isEmulator +
                    ", debugger=" + isDebuggerAttached +
                    ", signatureValid=" + isSignatureValid +
                    ", selinux=" + isSelinuxEnforcing +
                    ", verifiedBoot=" + isVerifiedBootGreen +
                    ", hardwareKey=" + isHardwareBackedKey +
                    ", deviceTrusted=" + isDeviceTrusted +
                    '}';
        }
    }
}
