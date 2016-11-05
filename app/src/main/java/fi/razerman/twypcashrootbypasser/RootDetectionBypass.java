package fi.razerman.twypcashrootbypasser;

/**
 * Created by Razerman on 5.11.2016.
 */


import android.util.Log;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import static de.robv.android.xposed.XC_MethodReplacement.returnConstant;

public class RootDetectionBypass implements IXposedHookLoadPackage {
    private static final String TAG = RootDetectionBypass.class.getSimpleName();

    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName.equals("es.ingdirect.twypcash")){
            Log.d(TAG, "Twyp Cash app detected, starting to bypass root detection!");

            // checkForBinary
            /* "/data/local/
            * "/data/local/bin/
            * "/data/local/xbin/
            * "/sbin/
            * "/system/bin/
            * /system/bin/.ext/
            * /system/bin/failsafe/
            * /system/sd/xbin/
            * /system/usr/we-need-root/
            * /system/xbin/ */
            // I believe it only checks for su and busybox binary from these paths but it's passed in as a parameter so it can check more files aswell
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "checkForBinary", String.class,
                    returnConstant(false)); // Check 1

            // checkForDangerousProps
            /* "ro.debuggable", "1"
            * "ro.secure", "0" */
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "checkForDangerousProps",
                    returnConstant(false)); // Check 1

            // checkForRWPaths
            /* /system
            * /system/bin
            * /system/sbin
            * /system/xbin
            * /vendor/bin
            * /sbin
            * /etc */
            // Checks if some of the previous paths is writabe and returns true (rooted) if they are
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "checkForRWPaths",
                    returnConstant(false)); // Check 1

            // checkSuExists
            // Another su binary check :D, now it apparently tries to execute it though
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "checkSuExists",
                    returnConstant(false)); // Check 1

            // detectPotentiallyDangerousApps
            /* com.koushikdutta.rommanager
            * com.dimonvideo.luckypatcher
            * com.chelpus.lackypatch
            * com.ramdroid.appquarantine */
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "detectPotentiallyDangerousApps",
                    android.content.Context.class, returnConstant(false)); // Check 1

            // detectRootCloakingApps
            /* com.devadvance.rootcloak
            * de.robv.android.xposed.installer
            * com.saurik.substrate
            * com.devadvance.rootcloakplus
            * com.zachspong.temprootremovejb
            * com.amphoras.hidemyroot
            * com.formyhm.hideroot */
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "detectRootCloakingApps",
                    android.content.Context.class, returnConstant(false)); // Check 1

            // detectRootManagementApps
            /* com.noshufou.android.su
            * com.noshufou.android.su.elite
            * eu.chainfire.supersu
            * com.koushikdutta.superuser
            * com.thirdparty.superuser
            * com.yellowes.su */
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "detectRootManagementApps",
                    android.content.Context.class, returnConstant(false)); // Check 1

            // detectTestKeys - test-keys
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "detectTestKeys",
                    returnConstant(false)); // Check 1

            // The method that calls all the previous methods. Basically could make only this return false but playing it safe and making all the others return false aswell
            findAndHookMethod("es.ingdirect.commons.utils.SecurityUtils", lpparam.classLoader, "isPhoneRooted",
                    android.content.Context.class, returnConstant(false)); // Check 1

            Log.d(TAG, "Bypassed Twyp Cash's root detection!");
        }
    }
}
