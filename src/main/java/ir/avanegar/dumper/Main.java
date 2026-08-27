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
            // هک سطح حافظه: خنثی کردن تله Anti-Debug در libc.so
            Module libc = memory.findModule("libc.so");
            Symbol clock_gettime = libc.findSymbolByName("clock_gettime");
            if (clock_gettime != null) {
                System.out.println("[+] HACKING RAM: Patching clock_gettime() to bypass Anti-Debug...");
                // تزریق اسمبلی به حافظه: mov x0, #0 (Success) ; ret
                byte[] patch = new byte[] { 0x00, 0x00, (byte)0x80, (byte)0xd2, (byte)0xc0, 0x03, 0x5f, (byte)0xd6 };
                emulator.getBackend().mem_write(clock_gettime.getAddress(), patch);
            }

            DalvikModule dm = vm.loadLibrary(new File("payload/libloader7007ea.so"), false);
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
            System.err.println("\n[-] CRASH OR EXCEPTION DURING UNPACKING:");
            e.printStackTrace();
        }
    }

    // دور زدن ارور ساخته نشدن کلاس مخفی
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
