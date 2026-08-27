package ir.avanegar.dumper;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class Main extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;

    public Main() {
        // ۱. ساخت یک پردازنده ۶۴ بیتی با اسم پکیج بدافزار
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("ir.avanegar.core").build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        // ۲. ردیابی سیستم‌کال‌ها (برای دیدن فایل‌هایی که بدافزار باز می‌کنه)
        emulator.getSyscallHandler().setVerbose(true);

        // ۳. ساخت ماشین مجازی جاوا (دروغین)
        vm = emulator.createDalvikVM(null);
        vm.setJni(this);
        // روشن کردن لاگ‌های JNI برای دیدن رمزگشایی و تزریق Dex
        vm.setVerbose(true); 

        // ۴. لود کردن فایل مخرب
        DalvikModule dm = vm.loadLibrary(new File("payload/libloader7007ea.so"), false);
        
        System.out.println("\n[+] Library loaded successfully. Calling JNI_OnLoad...\n");
        
        // ۵. اجرای نقطه شروع بدافزار
        try {
            dm.callJNI_OnLoad(emulator);
            System.out.println("\n[+] JNI_OnLoad finished successfully!");
        } catch (Exception e) {
            System.err.println("\n[-] Error or Anti-VM triggered:");
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Main();
    }
}

