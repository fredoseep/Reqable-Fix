package com.fredoseep.chelaile;

import android.app.Activity;
import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** Business hooks only; keep the working v5 Gadget script unchanged. */
public final class MainHook implements IXposedHookLoadPackage {
    private static final String TAG = "CLL.Entry";
    private static final String TARGET = "com.ygkj.chelaile.standard";
    private static boolean bootstrapInstalled;
    private static boolean vipComplete;
    private static boolean feedComplete;
    private static boolean installing;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) {
        if (!TARGET.equals(param.packageName) || !TARGET.equals(param.processName)) return;
        synchronized (MainHook.class) {
            if (bootstrapInstalled) return;
            bootstrapInstalled = true;
        }
        Log.i(TAG, "Module entry reached; defer business hooks until unpacking completes");

        try {
            XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            attemptFromContext((Context) p.thisObject, "Application.attach");
                        }
                    });
            Log.i(TAG, "Application.attach observer installed");
        } catch (Throwable e) { Log.e(TAG, "Install attach observer failed", e); }

        try {
            XposedHelpers.findAndHookMethod(Instrumentation.class, "callApplicationOnCreate",
                    Application.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            attemptFromContext((Context) p.args[0], "before Application.onCreate");
                        }
                    });
            Log.i(TAG, "Application.onCreate observer installed");
        } catch (Throwable e) { Log.e(TAG, "Install application observer failed", e); }

        // Some wrappers replace the application loader later. Activity provides
        // the loader actually used for business classes; successful hooks dedupe.
        try {
            XposedHelpers.findAndHookMethod(Activity.class, "onCreate", Bundle.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            attemptFromContext((Context) p.thisObject, "Activity.onCreate");
                        }
                    });
        } catch (Throwable e) { Log.e(TAG, "Install activity fallback failed", e); }
    }

    private static void attemptFromContext(Context context, String phase) {
        try {
            if (context == null || !TARGET.equals(context.getPackageName())) return;
            ClassLoader actual = context.getClass().getClassLoader();
            attempt(actual, phase + "/object-loader");
            ClassLoader contextLoader = context.getClassLoader();
            if (contextLoader != actual) attempt(contextLoader, phase + "/context-loader");
        } catch (Throwable e) { Log.e(TAG, "Lifecycle callback failed: " + phase, e); }
    }

    private static synchronized void attempt(ClassLoader loader, String phase) {
        if (loader == null || installing || (vipComplete && feedComplete)) return;
        installing = true;
        try {
            // Do not initialise target classes just to check visibility.
            boolean visible = false;
            for (String name : new String[] {
                    "dev.xesam.chelaile.sdk.query.api.HomeVipTip",
                    "dev.xesam.chelaile.app.module.feed.FeedWebViewFragment"}) {
                try {
                    Class.forName(name, false, loader);
                    visible = true;
                    break;
                } catch (ClassNotFoundException ignored) { }
            }
            if (!visible) {
                Log.i(TAG, "Business classes not visible yet: " + phase);
                return;
            }
            Log.i(TAG, "Business classes visible: " + phase + ", loader=" + loader);
            // Isolate feature installation: one failure must not skip the next feature.
            if (!vipComplete) {
                try { vipComplete = VipHook.hook(loader); }
                catch (Throwable e) { Log.e(TAG, "VIP installation failed", e); }
            }
            if (!feedComplete) {
                try { feedComplete = FeedWebViewRemove.hook(loader); }
                catch (Throwable e) { Log.e(TAG, "Feed installation failed", e); }
            }
            Log.i(TAG, "Installation state: vip=" + vipComplete + ", feed=" + feedComplete);
        } catch (Throwable e) { Log.e(TAG, "Install attempt failed: " + phase, e); }
        finally { installing = false; }
    }
}
