package ir.avanegar.dumper;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class Main extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;

    public Main() {
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("ir.avanegar.core").build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM((File) null);
        vm.setJni(this);
        vm.setVerbose(true);

        System.out.println("=== STARTING UNIDBG ANALYSIS (PURE TRACING MODE) ===");

        try {
            DalvikModule dm = vm.loadLibrary(new File("payload/libloader7007ea.so"), false);
            
            Module libc = memory.findModule("libc.so");
            if (libc != null) {
                // ۱. خنثی کردن تایمر (Anti-Debug)
                Symbol clock_gettime = libc.findSymbolByName("clock_gettime");
                if (clock_gettime != null) {
                    byte[] patch = new byte[] { 0x00, 0x00, (byte)0x80, (byte)0xd2, (byte)0xc0, 0x03, 0x5f, (byte)0xd6 };
                    emulator.getBackend().mem_write(clock_gettime.getAddress(), patch);
                }
                // ۲. خنثی کردن دستور خروج (exit) تا بدافزار بسته نشه
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

            // روشن کردن دوربین مداربسته لینوکسی
            emulator.getSyscallHandler().setVerbose(true);

            System.out.println("\n[+] FIRE: Calling nativeSetup()...");
            baseAppObj.callJniMethod(emulator, "nativeSetup(Ljava/lang/ClassLoader;)V", classLoaderObj);

            System.out.println("\n[+] FIRE: Calling nativeBind()...");
            baseAppObj.callJniMethod(emulator, "nativeBind(Landroid/content/Context;)V", baseAppObj);

            emulator.getSyscallHandler().setVerbose(false);

        } catch (Exception e) {
            System.out.println("\n[-] EXCEPTION DETECTED:");
            e.printStackTrace(System.out);
        }
    }

    // برطرف کردن نیازهای جاوا (کلاس‌ها و متدها)
    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("ir/avanegar/core/App-><init>()V".equals(signature)) {
            return dvmClass.newObject(null);
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

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("ir/avanegar/core/App->attach(Landroid/content/Context;)V".equals(signature)) {
            return; 
        }
        if ("ir/avanegar/core/App->onCreate()V".equals(signature)) {
            return; 
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    public static void main(String[] args) {
        new Main();
    }
}
