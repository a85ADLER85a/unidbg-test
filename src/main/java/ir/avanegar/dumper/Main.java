package ir.avanegar.dumper;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class Main extends AbstractJni implements IOResolver<AndroidFileIO> {
    private final AndroidEmulator emulator;
    private final VM vm;

    public Main() {
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("ir.avanegar.core").build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        emulator.getSyscallHandler().addIOResolver(this);

        vm = emulator.createDalvikVM((File) null);
        vm.setJni(this);
        vm.setVerbose(true); // نمایش تمام عملیات‌های جاوا (برای دیدن لحظه شکار)

        System.out.println("=== STARTING UNIDBG ANALYSIS (SNIPER MODE) ===");

        try {
            DalvikModule dm = vm.loadLibrary(new File("payload/libloader7007ea.so"), false);
            
            Module libc = memory.findModule("libc.so");
            if (libc != null) {
                Symbol clock_gettime = libc.findSymbolByName("clock_gettime");
                if (clock_gettime != null) {
                    byte[] patch = new byte[] { 0x00, 0x00, (byte)0x80, (byte)0xd2, (byte)0xc0, 0x03, 0x5f, (byte)0xd6 };
                    emulator.getBackend().mem_write(clock_gettime.getAddress(), patch);
                }
                Symbol exit = libc.findSymbolByName("exit");
                if (exit != null) {
                    emulator.getBackend().mem_write(exit.getAddress(), new byte[] { (byte)0xc0, 0x03, 0x5f, (byte)0xd6 });
                }
            }

            dm.callJNI_OnLoad(emulator);
            
            DvmClass baseAppClass = vm.resolveClass("org/support/internal/BaseApplication");
            DvmObject<?> baseAppObj = baseAppClass.newObject(null);
            DvmClass classLoaderClass = vm.resolveClass("java/lang/ClassLoader");
            DvmObject<?> classLoaderObj = classLoaderClass.newObject(null);

            System.out.println("\n[+] FIRE: Calling nativeSetup()... (THIS MIGHT TAKE 5-10 MINUTES, BE PATIENT!)");
            baseAppObj.callJniMethod(emulator, "nativeSetup(Ljava/lang/ClassLoader;)V", classLoaderObj);

            System.out.println("\n[+] FIRE: Calling nativeBind()...");
            baseAppObj.callJniMethod(emulator, "nativeBind(Landroid/content/Context;)V", baseAppObj);

        } catch (Exception e) {
            System.out.println("\n[-] EXCEPTION DETECTED:");
            e.printStackTrace(System.out);
        }
    }

    // هدایتگر فایل: دادنِ همون APK واقعیِ ۲ مگابایتی به بدافزار
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        if (pathname.contains("base.apk")) {
            System.out.println("\n[!] VFS HOOK: Redirecting to REAL MALWARE APK!");
            return FileResult.success(new SimpleFileIO(oflags, new File("payload/real_malware.apk"), pathname));
        }
        // اگر بدافزار سعی کنه دکس رو روی هارد ذخیره کنه مچش رو می‌گیریم
        if (pathname.endsWith(".dex") || pathname.endsWith(".jar")) {
            System.out.println("\n[🎯 SNIPER BINGO] Packer is writing decrypted file to disk: " + pathname);
            System.exit(0); // شلیک نهایی و بستن شبیه‌ساز برای ذخیره وقت
        }
        return null;
    }

    // تک‌تیرانداز جاوا: شنود کلاس‌ها و فایل‌های دکسِ در حال بارگذاری
    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.contains("ir/avanegar/core/App-><init>()V")) {
            return dvmClass.newObject(null);
        }
        if (signature.contains("DexClassLoader") || signature.contains("InMemoryDexClassLoader")) {
            System.out.println("\n[🎯 SNIPER BINGO] Packer is loading the decrypted DEX into RAM!");
            System.out.println("[🎯] Hook Intercepted: " + signature);
            System.exit(0); // شلیک نهایی!
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/app/ActivityThread->mBoundApplication:Landroid/app/ActivityThread$AppBindData;".equals(signature)) {
            return vm.resolveClass("android/app/ActivityThread$AppBindData").newObject(null);
        }
        if ("android/app/ActivityThread$AppBindData->appInfo:Landroid/content/pm/ApplicationInfo;".equals(signature)) {
            return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(null);
        }
        if ("android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "/data/app/ir.avanegar.core/base.apk");
        }
        if ("android/content/pm/ApplicationInfo->dataDir:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "/data/data/ir.avanegar.core");
        }
        return super.getObjectField(vm, dvmObject, signature);
    }

    // تک‌تیرانداز حافظه رم: بررسی بایت‌های در حال انتقال در JNI
    @Override
    public void setByteArrayRegion(BaseVM vm, DvmObject<?> dvmObject, int start, int length, byte[] bytes) {
        if (bytes != null && bytes.length > 8) {
             // چک کردن Magic Number فایل دکس (dex\n)
             if (bytes[0] == 0x64 && bytes[1] == 0x65 && bytes[2] == 0x78 && bytes[3] == 0x0a) {
                 System.out.println("\n[🎯 SNIPER BINGO] 'dex\\n035' MAGIC DETECTED IN RAM!");
                 System.out.println("[🎯] Size of decrypted DEX: " + bytes.length + " bytes");
                 System.exit(0); // شلیک نهایی!
             }
        }
        super.setByteArrayRegion(vm, dvmObject, start, length, bytes);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("ir/avanegar/core/App->attach(Landroid/content/Context;)V".equals(signature)) { return; }
        if ("ir/avanegar/core/App->onCreate()V".equals(signature)) { return; }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    public static void main(String[] args) {
        new Main();
    }
}
