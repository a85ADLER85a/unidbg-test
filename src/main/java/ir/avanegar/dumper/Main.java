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
            DalvikModule dm = vm.loadLibrary(new File("payload/libloader7007ea.so"), false);
            
            Module libc = memory.findModule("libc.so");
            if (libc != null) {
                Symbol clock_gettime = libc.findSymbolByName("clock_gettime");
                if (clock_gettime != null) {
                    byte[] patch = new byte[] { 0x00, 0x00, (byte)0x80, (byte)0xd2, (byte)0xc0, 0x03, 0x5f, (byte)0xd6 };
                    emulator.getBackend().mem_write(clock_gettime.getAddress(), patch);
                }
            }

            dm.callJNI_OnLoad(emulator);
            
            DvmClass baseAppClass = vm.resolveClass("org/support/internal/BaseApplication");
            DvmObject<?> baseAppObj = baseAppClass.newObject(null);
            DvmClass classLoaderClass = vm.resolveClass("java/lang/ClassLoader");
            DvmObject<?> classLoaderObj = classLoaderClass.newObject(null);

            System.out.println("\n[+] FIRE: Calling nativeSetup()...");
            baseAppObj.callJniMethod(emulator, "nativeSetup(Ljava/lang/ClassLoader;)V", classLoaderObj);

            System.out.println("\n[+] FIRE: Calling nativeBind()...");
            baseAppObj.callJniMethod(emulator, "nativeBind(Landroid/content/Context;)V", baseAppObj);

        } catch (Exception e) {
            System.out.println("\n[-] CRASH DETECTED:");
            e.printStackTrace(System.out);
        }
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("ir/avanegar/core/App-><init>()V".equals(signature)) {
            return dvmClass.newObject(null);
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    // اضافه شدن جعل ApplicationInfo برای بدافزار
    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/app/ActivityThread->mBoundApplication:Landroid/app/ActivityThread$AppBindData;".equals(signature)) {
            System.out.println("[+] MOCK: Giving fake AppBindData");
            return vm.resolveClass("android/app/ActivityThread$AppBindData").newObject(null);
        }
        if ("android/app/ActivityThread$AppBindData->appInfo:Landroid/content/pm/ApplicationInfo;".equals(signature)) {
            System.out.println("[+] MOCK: Giving fake ApplicationInfo");
            return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(null);
        }
        return super.getObjectField(vm, dvmObject, signature);
    }

    // مسدود کردن فراخوانی onCreate علاوه بر attach
    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("ir/avanegar/core/App->attach(Landroid/content/Context;)V".equals(signature)) {
            System.out.println("[+] MOCK: Ignoring attach() call");
            return; 
        }
        if ("ir/avanegar/core/App->onCreate()V".equals(signature)) {
            System.out.println("[+] MOCK: Ignoring onCreate() call");
            return; 
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    public static void main(String[] args) {
        new Main();
    }
}
