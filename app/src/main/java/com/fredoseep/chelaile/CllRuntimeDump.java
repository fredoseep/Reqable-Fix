package com.fredoseep.chelaile;// 在这里添加你自己的 package 声明。

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * 车来了运行时 DEX 诊断导出，适用于当前 ARM64 设备。
 *
 * 入口（放在“非微信直接 return”之前）：
 * if ("com.ygkj.chelaile.standard".equals(lpparam.packageName)) {
 *     CllRuntimeDump.install();
 *     return;
 * }
 *
 * 此类不包含 v4 启动修复，启动仍须沿用已验证的修复。
 * 输出：应用 files/runtime_dex/PID/；日志 TAG：CLL.DexDump。
 *
 * cookie 是 ART 的 native 对象句柄，不是 HTTP Cookie。
 * 此处 long[] cookie 第 0 项为 OatFile，后续项为 DexFile 地址。
 * 这些地址只在当前进程、对象有效期间有意义，不能跨启动复用。
 *
 * DexCache、cookie 和 native 布局都是实现细节，不保证各系统通用。
 * 类元数据可见不等于方法字节码完整；本类不会补回抽取的 code_item。
 * try/catch 只能隔离 Java 异常，不能拦住 SIGSEGV/SIGKILL 等原生故障。
 * v2：依据 24823.zip 中的 ARM64 快照增加对象范围导出；不依赖标准 DEX 头。
 * object-span_*.raw.bin 为原样内存，不能仅改后缀就保证可被 JADX 识别。
 * header_*.bin / object_*.txt 保存被过滤原因，供后续还原头部。
 * 修改后尚未实机验证。
 */
public final class CllRuntimeDump {
    private static final String TAG = "CLL.DexDump";
    private static final String TARGET = "com.ygkj.chelaile.standard";
    private static final long MAX_DEX_SIZE = 256L * 1024 * 1024;

    // 以下导出状态只在单线程 WORKER 中使用。
    private static final Set<Class<?>> CLASSES = new HashSet<>();
    private static final Set<ClassLoader> LOADERS = new HashSet<>();
    private static final Set<Long> NATIVE_OBJECTS = new HashSet<>();
    private static final Set<Long> DEX_ADDRESSES = new HashSet<>();
    private static ExecutorService worker;
    private static boolean installed;
    private static File outputDir;
    private static FileDescriptor memoryFd;

    private CllRuntimeDump() {}

    /** 注册失败只记日志；成功后才设置 installed，允许失败后再次调用。 */
    public static synchronized void install() {
        if (installed) return;
        try {
            final ExecutorService executor = getWorker();
            XposedHelpers.findAndHookMethod(Activity.class, "onResume",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            // 边界二：整个 Hook 回调，包括取对象和提交任务。
                            try {
                                Activity activity = (Activity) param.thisObject;
                                if (!TARGET.equals(activity.getPackageName())) return;
                                final Application app = activity.getApplication();
                                if (app == null) return;
                                final Class<?> activityClass = activity.getClass();
                                // 不在主线程执行读取和导出；不持有 Activity。
                                executor.execute(() -> {
                                    // 边界三：后台任务，不能靠回调外层 catch 捕获。
                                    try {
                                        initialize(app);
                                        inspectClass(activityClass);
                                        inspectClass(app.getClass());
                                        inspectLoader(activityClass.getClassLoader());
                                        inspectLoader(app.getClassLoader());
                                    } catch (Throwable e) {
                                        Log.e(TAG, "Background dump failed", e);
                                    }
                                });
                            } catch (Throwable e) {
                                Log.e(TAG, "Activity.onResume callback failed", e);
                            }
                        }
                    });
            installed = true;
            Log.i(TAG, "Activity.onResume dump hook installed");
        } catch (Throwable e) {
            // 边界一：查找方法、注册 Hook、创建执行器的异常。
            Log.e(TAG, "Install Activity.onResume hook failed", e);
        }
    }

    private static synchronized ExecutorService getWorker() {
        if (worker == null || worker.isShutdown()) {
            worker = Executors.newSingleThreadExecutor();
        }
        return worker;
    }

    private static void initialize(Context context) throws Exception {
        if (outputDir == null) {
            File dir = new File(context.getFilesDir(), "runtime_dex/" + Process.myPid());
            if (!dir.isDirectory() && !dir.mkdirs()) {
                throw new IllegalStateException("Cannot create " + dir);
            }
            outputDir = dir;
            Log.i(TAG, "Output: " + dir.getAbsolutePath());
        }
        if (memoryFd == null) {
            memoryFd = Os.open("/proc/self/mem", OsConstants.O_RDONLY, 0);
        }
    }

    /** 实际业务 Class -> dexCache -> native DexFile。 */
    private static void inspectClass(Class<?> clazz) {
        if (clazz == null || !CLASSES.add(clazz)) return;
        Log.i(TAG, "Inspect class: " + clazz.getName());
        saveClassMetadata(clazz);
        try {
            Object cache = getField(clazz, "dexCache");
            if (cache == null) {
                Log.i(TAG, "dexCache is null: " + clazz.getName());
                return;
            }
            Object value = getField(cache, "dexFile");
            if (!(value instanceof Number)) {
                Log.i(TAG, "Unexpected dexFile field: " + value);
                return;
            }
            inspectNativeDexFile(((Number) value).longValue(),
                    "Class.dexCache: " + clazz.getName());
        } catch (Throwable e) {
            CLASSES.remove(clazz); // 本次失败，下次 onResume 可以重试。
            Log.e(TAG, "Class.dexCache route failed: " + clazz.getName(), e);
        }
    }

    private static void saveClassMetadata(Class<?> clazz) {
        String name = clazz.getName().replaceAll("[^a-zA-Z0-9._-]", "_")
                + "_" + System.identityHashCode(clazz.getClassLoader()) + ".txt";
        try (PrintWriter out = new PrintWriter(new File(outputDir, name), "UTF-8")) {
            out.println("CLASS: " + clazz.getName());
            out.println("LOADER: " + clazz.getClassLoader());
            Class<?> parent = clazz.getSuperclass();
            out.println("SUPER: " + (parent == null ? "null" : parent.getName()));
            out.println("\nFIELDS:");
            try {
                for (Field f : clazz.getDeclaredFields()) out.println(f.toGenericString());
            } catch (Throwable e) { out.println("ERROR: " + e); }
            out.println("\nCONSTRUCTORS:");
            try {
                for (Constructor<?> c : clazz.getDeclaredConstructors()) {
                    out.println(c.toGenericString());
                }
            } catch (Throwable e) { out.println("ERROR: " + e); }
            out.println("\nMETHODS:");
            try {
                for (Method m : clazz.getDeclaredMethods()) out.println(m.toGenericString());
            } catch (Throwable e) { out.println("ERROR: " + e); }
            if (out.checkError()) Log.e(TAG, "Class metadata write error: " + name);
        } catch (Throwable e) {
            Log.e(TAG, "Save class metadata failed", e);
        }
    }

    /** 补充检查实际 Activity 的 ClassLoader 和父加载器。 */
    private static void inspectLoader(ClassLoader loader) {
        while (loader != null) {
            if (!LOADERS.contains(loader)) {
                try {
                    Log.i(TAG, "Inspect loader: " + loader);
                    Object elements = getField(getField(loader, "pathList"), "dexElements");
                    boolean complete = true;
                    for (int i = 0; i < Array.getLength(elements); i++) {
                        try {
                            Object element = Array.get(elements, i);
                            if (element == null) continue;
                            Object dex = getField(element, "dexFile");
                            if (dex == null) continue;
                            Log.i(TAG, "Dex element: " + dex);
                            inspectCookie(dex, "mCookie");
                            inspectCookie(dex, "mInternalCookie");
                        } catch (Throwable e) {
                            complete = false;
                            Log.e(TAG, "Inspect dex element " + i + " failed", e);
                        }
                    }
                    if (complete) LOADERS.add(loader);
                } catch (Throwable e) {
                    Log.i(TAG, "Loader pathList unavailable: "
                            + loader.getClass().getName() + ": " + e);
                }
            }
            try {
                loader = loader.getParent();
            } catch (Throwable e) {
                Log.e(TAG, "Get parent loader failed", e);
                break;
            }
        }
    }

    private static void inspectCookie(Object dexFile, String fieldName) {
        try {
            Object cookie = getField(dexFile, fieldName);
            if (!(cookie instanceof long[])) return;
            long[] values = (long[]) cookie;
            // 不将第 0 项的 OatFile 误当成 DexFile。
            for (int i = 1; i < values.length; i++) {
                inspectNativeDexFile(values[i], fieldName + ": " + dexFile);
            }
        } catch (Throwable e) {
            Log.i(TAG, fieldName + " unavailable: " + e);
        }
    }

    private static void inspectNativeDexFile(long address, String source) {
        if (address < 0x10000L || NATIVE_OBJECTS.contains(address)) return;
        String name = Long.toHexString(address);
        try {
            // 当前 ARM64 方案：检查对象头部有限范围中的指针，不写死 begin_ 偏移。
            byte[] object = readMemory(address, 0x100);
            writeBytes(new File(outputDir, "object_" + name + ".bin"), object);
            try (PrintWriter out = new PrintWriter(
                    new File(outputDir, "object_" + name + ".txt"), "UTF-8")) {
                out.println("SOURCE: " + source);
                out.println("OBJECT: " + hex(address));
                ByteBuffer b = ByteBuffer.wrap(object).order(ByteOrder.LITTLE_ENDIAN);
                inspectObjectSpan(b, out);
                for (int off = 0; off + 8 <= object.length; off += 8) {
                    long pointer = b.getLong(off);
                    out.println("+" + Integer.toHexString(off) + " -> " + hex(pointer));
                    if (pointer >= 0x10000L && pointer < (1L << 56)) {
                        inspectDexCandidate(pointer, out);
                    }
                }
                if (out.checkError()) throw new IllegalStateException("Diagnostic write failed");
            }
            NATIVE_OBJECTS.add(address);
        } catch (Throwable e) {
            Log.e(TAG, "Read native DexFile failed: " + hex(address), e);
        }
    }

    /**
     * 仅匹配本次 ARM64 快照：+8、+18、+48 是相同起点，+20 是范围长度。
     * 以相同 vtable 的壳对象作对照，这三个起点和长度与已导出的壳完全吻合。
     * 仍是当前设备的布局假设，因此只输出 raw，不伪装成已经修复的 DEX。
     */
    private static void inspectObjectSpan(ByteBuffer object, PrintWriter diagnostic)
            throws Exception {
        long begin = object.getLong(0x18);
        long size = object.getLong(0x20);
        boolean layout = begin >= 0x10000L && begin < (1L << 56)
                && begin == object.getLong(0x08) && begin == object.getLong(0x48)
                && size >= 0x70 && size <= MAX_DEX_SIZE;
        // 已观察到的六个表指针必须都位于对象给出的范围内。
        int[] fields = {0x50, 0x58, 0x60, 0x68, 0x70, 0x78};
        for (int field : fields) {
            long table = object.getLong(field);
            if (table < begin + 0x70 || table >= begin + size) layout = false;
        }
        if (!layout) {
            diagnostic.println("OBJECT-SPAN: layout mismatch; skipped");
            return;
        }
        diagnostic.println("OBJECT-SPAN: begin=" + hex(begin) + ", size=" + size
                + ", end=" + hex(begin + size));
        byte[] h = readMemory(begin, 0x70);
        writeBytes(new File(outputDir, "header_" + Long.toHexString(begin) + ".bin"), h);
        diagnostic.println("HEADER bytes: " + headerHex(h, h.length));
        diagnostic.println("HEADER file_size=" + u32(h, 0x20)
                + ", header_size=" + hex(u32(h, 0x24))
                + ", endian_tag=" + hex(u32(h, 0x28))
                + ", class_defs_size=" + u32(h, 0x60));
        boolean standard = u32(h, 0x24) == 0x70
                && u32(h, 0x28) == 0x12345678L
                && u32(h, 0x20) == size && validTables(h, size);
        diagnostic.println("STANDARD-HEADER: " + standard);
        if (standard) return; // 后面的标准候选导出负责此对象。
        File raw = new File(outputDir, "object-span_" + Long.toHexString(begin)
                + ".raw.bin");
        // 原始数据始终保留，不补 magic、不猜 class_defs_size、不改校验和。
        if (!raw.isFile() || raw.length() != size) {
            dumpMemory(begin, size, raw);
            Log.i(TAG, "Dumped object span: " + raw.getAbsolutePath() + ", size=" + size);
        }
        diagnostic.println("RAW-DUMP: " + raw.getName() + ", size=" + raw.length());
    }

    private static void inspectDexCandidate(long address, PrintWriter diagnostic) {
        try {
            byte[] h = readMemory(address, 0x70);
            long size = u32(h, 0x20);
            if (u32(h, 0x24) != 0x70 || u32(h, 0x28) != 0x12345678L
                    || size < 0x70 || size > MAX_DEX_SIZE || !validTables(h, size)) {
                return;
            }
            diagnostic.println("  DEX candidate: size=" + size + ", classes="
                    + u32(h, 0x60) + ", magic=" + headerHex(h, 8));
            if (DEX_ADDRESSES.contains(address)) return;
            boolean magic = h[0] == 'd' && h[1] == 'e' && h[2] == 'x' && h[3] == '\n';
            File file = new File(outputDir, "dex_" + Long.toHexString(address)
                    + (magic ? ".dex" : ".bin"));
            dumpMemory(address, size, file);
            DEX_ADDRESSES.add(address); // 只有完整写入后才去重，失败仍允许重试。
            Log.i(TAG, "Dumped: " + file.getAbsolutePath() + ", size=" + size
                    + ", classes=" + u32(h, 0x60));
        } catch (Throwable e) {
            diagnostic.println("  Candidate read failed: " + hex(address) + ": " + e);
        }
    }

    private static boolean validTables(byte[] h, long fileSize) {
        int[][] tables = {{0x38, 0x3c, 4}, {0x40, 0x44, 4}, {0x48, 0x4c, 12},
                {0x50, 0x54, 8}, {0x58, 0x5c, 8}, {0x60, 0x64, 32}};
        for (int[] t : tables) {
            long count = u32(h, t[0]), offset = u32(h, t[1]);
            if (count != 0 && (offset < 0x70 || (offset & 3) != 0
                    || offset + count * t[2] > fileSize)) return false;
        }
        long map = u32(h, 0x34), size = u32(h, 0x68), off = u32(h, 0x6c);
        if (map != 0 && (map < 0x70 || map >= fileSize || (map & 3) != 0)) return false;
        return size == 0 || (off >= 0x70 && off + size <= fileSize);
    }

    private static byte[] readMemory(long address, int size) throws Exception {
        byte[] result = new byte[size];
        readFully(address, result, size);
        return result;
    }

    private static void readFully(long address, byte[] buffer, int size) throws Exception {
        int done = 0;
        while (done < size) {
            int n = Os.pread(memoryFd, buffer, done, size - done, address + done);
            if (n <= 0) throw new IllegalStateException("Short memory read: " + hex(address + done));
            done += n;
        }
    }

    private static void dumpMemory(long address, long size, File file) throws Exception {
        File part = new File(file.getPath() + ".part");
        try (FileOutputStream out = new FileOutputStream(part)) {
            byte[] buffer = new byte[64 * 1024];
            for (long off = 0; off < size;) {
                int n = (int) Math.min(buffer.length, size - off);
                readFully(address + off, buffer, n);
                out.write(buffer, 0, n);
                off += n;
            }
        }
        // 失败时保留 .part，避免把部分文件当成完整 DEX。
        if (!part.renameTo(file)) throw new IllegalStateException("Cannot rename " + part);
    }

    private static Object getField(Object object, String name) throws Exception {
        if (object == null) throw new NullPointerException(name + ": object is null");
        for (Class<?> c = object.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(object);
            } catch (NoSuchFieldException ignored) { }
        }
        throw new NoSuchFieldException(object.getClass().getName() + "." + name);
    }

    private static long u32(byte[] b, int o) {
        return ((long) b[o] & 255) | (((long) b[o + 1] & 255) << 8)
                | (((long) b[o + 2] & 255) << 16) | (((long) b[o + 3] & 255) << 24);
    }

    private static String hex(long v) { return "0x" + Long.toHexString(v); }

    private static String headerHex(byte[] b, int n) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n; i++) s.append(String.format(Locale.ROOT, "%02x", b[i] & 255));
        return s.toString();
    }

    private static void writeBytes(File file, byte[] bytes) throws Exception {
        try (FileOutputStream out = new FileOutputStream(file)) { out.write(bytes); }
    }
}
