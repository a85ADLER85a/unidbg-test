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

        System.out.println("=== STARTING UNIDBG ANALYSIS ===");

        try {
            // ۱. اول لودر بدافزار رو لود می‌کنیم تا سیستم‌عامل اندروید تو رم شبیه‌سازی بشه
            DalvikModule dm = vm.loadLibrary(new File("payload/libloader7007ea.so"), false);
            
            // ۲. حالا که رم پر شده، تله رو خنثی می‌کنیم (جراحی حافظه)
            Module libc = memory.findModule("libc.so");
            if (libc != null) {
                Symbol clock_gettime = libc.findSymbolByName("clock_gettime");
                if (clock_gettime != null) {
                    System.out.println("[+] HACKING RAM: Patching clock_gettime() to bypass Anti-Debug...");
                    byte[] patch = new byte[] { 0x00, 0x00, (byte)0x80, (byte)0xd2, (byte)0xc0, 0x03, 0x5f, (byte)0xd6 };
                    emulator.getBackend().mem_write(clock_gettime.getAddress(), patch);
                }
            }

            // ۳. اجرای توابع بدافزار
            dm.callJNI_OnLoad(emulator);
            
            System.out.println("\n[+] Resolving Target Class...");
            DvmClass baseAppClass = vm.resolveClass("org/support/internal/BaseApplication");
            DvmObject<?> baseAppObj = baseAppClass.newObject(null);

            DvmClass classLoaderClass = vm.resolveClass("java/lang/ClassLoader");
            DvmObject<?> classLoaderObj = classLoaderClass.newObject(null);

            System.out.println("\n[+] FIRE: Calling nativeSetup()...");
            baseAppObj.callJniMethod(emulator, "nativeSetup(Ljava/lang/ClassLoader;)V", classLoaderObj);

            System.out.println("\n[+] FIRE: Calling nativeBind()...");
            baseAppObj.callJniMethod(emulator, "nativeBind(Landroid/content/Context;)V", baseAppObj);

        } catch (Exception e) {
            // چاپ خطاها در مسیر استاندارد تا تو فایل متنی ذخیره بشه
            System.out.println("\n[-] CRASH OR EXCEPTION DURING UNPACKING:");
            e.printStackTrace(System.out); 
        }
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("ir/avanegar/core/App-><init>()V".equals(signature)) {
            System.out.println("[+] Bypassing ir.avanegar.core.App constructor call!");
            return dvmClass.newObject(null);
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    public static void main(String[] args) {
        new Main();
    }
}
