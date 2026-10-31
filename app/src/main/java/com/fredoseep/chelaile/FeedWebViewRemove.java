package com.fredoseep.chelaile;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.LinearLayout;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public final class FeedWebViewRemove {
    private static final String TAG = "CLL.Feed";
    private static final Set<Method> INSTALLED = new HashSet<>();

    private FeedWebViewRemove() { }

    public static synchronized boolean hook(ClassLoader loader) {
        boolean fragment = installFragment(loader);
        boolean container = installMeasure(loader,
                "dev.xesam.chelaile.app.module.line.ui.linedetail.LineDetailFeedContainerLayout",
                "cll_feed_main_layout", true);
        boolean movable = installMeasure(loader,
                "dev.xesam.chelaile.app.module.line.ui.linedetail.widgets.VerticalMovableContainer",
                null, false);
        return fragment && container && movable;
    }

    private static boolean installFragment(ClassLoader loader) {
        try {
            Class<?> clazz = Class.forName(
                    "dev.xesam.chelaile.app.module.feed.FeedWebViewFragment", false, loader);
            Method method = clazz.getDeclaredMethod("onViewCreated", View.class, Bundle.class);
            if (INSTALLED.contains(method)) return true;
            AtomicBoolean firstHit = new AtomicBoolean();
            XposedBridge.hookMethod(method, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        param.setResult(null); // Same behavior as the original DO_NOTHING.
                        if (firstHit.compareAndSet(false, true)) {
                            Log.i(TAG, "First hit: FeedWebViewFragment.onViewCreated skipped");
                        }
                    } catch (Throwable e) { Log.e(TAG, "Fragment callback failed", e); }
                }
            });
            INSTALLED.add(method);
            Log.i(TAG, "Installed: " + method);
            return true;
        } catch (Throwable e) { Log.e(TAG, "Fragment hook not installed", e); return false; }
    }

    private static boolean installMeasure(ClassLoader loader, String name,
                                          String resourceName, boolean inheritedLinearLayout) {
        try {
            Class<?> target = Class.forName(name, false, loader);
            // The supplied DEX confirms LineDetailFeedContainerLayout inherits
            // LinearLayout.onMeasure, while VerticalMovableContainer overrides it.
            Method method = (inheritedLinearLayout ? LinearLayout.class : target)
                    .getDeclaredMethod("onMeasure", int.class, int.class);
            if (INSTALLED.contains(method)) return true;
            AtomicBoolean firstHit = new AtomicBoolean();
            XposedBridge.hookMethod(method, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (!target.isInstance(param.thisObject)) return;
                        View view = (View) param.thisObject;
                        if (resourceName != null) {
                            if (view.getId() == View.NO_ID) return;
                            try {
                                if (!resourceName.equals(view.getResources()
                                        .getResourceEntryName(view.getId()))) return;
                            } catch (android.content.res.Resources.NotFoundException ignored) {
                                return;
                            }
                        }
                        XposedHelpers.callMethod(view, "setMeasuredDimension", 0, 0);
                        param.setResult(null);
                        if (firstHit.compareAndSet(false, true)) {
                            Log.i(TAG, "First hit: zero size " + name);
                        }
                    } catch (Throwable e) { Log.e(TAG, "Measure callback failed: " + name, e); }
                }
            });
            INSTALLED.add(method);
            Log.i(TAG, "Installed: " + method + ", target=" + name);
            return true;
        } catch (Throwable e) { Log.e(TAG, "Measure hook not installed: " + name, e); return false; }
    }
}
