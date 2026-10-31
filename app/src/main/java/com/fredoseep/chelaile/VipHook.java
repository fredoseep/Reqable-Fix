package com.fredoseep.chelaile;

import android.util.Log;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

public final class VipHook {
    private static final String TAG = "CLL.Vip";
    private static final Set<Method> INSTALLED = new HashSet<>();

    private VipHook() { }

    /** Returns true only when all three independent hooks were installed. */
    public static synchronized boolean hook(ClassLoader loader) {
        boolean hasVip = install(loader,
                "dev.xesam.chelaile.sdk.query.api.HomeVipTip", "hasVip", true);
        boolean valid = install(loader,
                "dev.xesam.chelaile.sdk.query.api.HomeVipTip", "valid", true);
        boolean adValid = install(loader,
                "dev.xesam.chelaile.app.ad.AdConfigDataConverter", "isValidAdData", false,
                "dev.xesam.chelaile.app.ad.data.AdData");
        return hasVip && valid && adValid;
    }

    private static boolean install(ClassLoader loader, String owner, String name,
                                   boolean result, String... parameters) {
        try {
            Class<?> clazz = Class.forName(owner, false, loader);
            Class<?>[] types = new Class<?>[parameters.length];
            for (int i = 0; i < types.length; i++) {
                types[i] = Class.forName(parameters[i], false, loader);
            }
            Method method = clazz.getDeclaredMethod(name, types);
            if (method.getReturnType() != boolean.class) {
                throw new IllegalStateException("Expected boolean: " + method);
            }
            if (INSTALLED.contains(method)) return true;
            AtomicBoolean firstHit = new AtomicBoolean();
            XposedBridge.hookMethod(method, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        // Preserve the original module's after-hook semantics.
                        param.setResult(result);
                        if (firstHit.compareAndSet(false, true)) {
                            Log.i(TAG, "First hit: " + name + " -> " + result);
                        }
                    } catch (Throwable e) { Log.e(TAG, "Callback failed: " + name, e); }
                }
            });
            INSTALLED.add(method);
            Log.i(TAG, "Installed: " + method);
            return true;
        } catch (Throwable e) {
            Log.e(TAG, "Not installed: " + owner + "#" + name, e);
            return false;
        }
    }
}
