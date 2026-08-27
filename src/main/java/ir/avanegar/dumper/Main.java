package ir.avanegar.dumper;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
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
        vm.setVerbose(true); // اینو روشن کردیم که لاگ JNI رو دقیق ببینیم

        System.out.println("=== STARTING UNIDBG ANALYSIS ===");

        try {
            DalvikModule dm = vm.loadLibrary(new File("payload/libloader7007ea.so"), false);
            dm.callJNI_OnLoad(emulator);
            System.out.println("[+] JNI_OnLoad executed successfully!");

            // ۱. پیدا کردن کلاسی که بدافزار توابعش رو اونجا مخفی کرده
            System.out.println("\n[+] Resolving Target Class...");
            DvmClass baseAppClass = vm.resolveClass("org/support/internal/BaseApplication");
            DvmObject<?> baseAppObj = baseAppClass.newObject(null);

            // ۲. ساخت یک ClassLoader و Context جعلی برای فریب دادن بدافزار
            DvmClass classLoaderClass = vm.resolveClass("java/lang/ClassLoader");
            DvmObject<?> classLoaderObj = classLoaderClass.newObject(null);

            // ۳. کشیدن ماشه! اجرای اجباری تابع nativeSetup
            System.out.println("\n[+] FIRE: Calling nativeSetup()...");
            baseAppObj.callJniMethod(emulator, "nativeSetup(Ljava/lang/ClassLoader;)V", classLoaderObj);

            // ۴. اجرای اجباری تابع nativeBind
            System.out.println("\n[+] FIRE: Calling nativeBind()...");
            baseAppObj.callJniMethod(emulator, "nativeBind(Landroid/content/Context;)V", baseAppObj);

        } catch (Exception e) {
            System.err.println("\n[-] CRASH OR EXCEPTION DURING UNPACKING:");
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Main();
    }
}
