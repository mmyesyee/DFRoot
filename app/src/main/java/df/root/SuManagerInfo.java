package df.root;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;

import java.util.ArrayList;
import java.util.List;

/** An installed SU manager that ships a ksud the exploit can stage. */
final class SuManagerInfo {

    final String packageName;
    final CharSequence label;
    final Drawable icon;

    private SuManagerInfo(String pkg, CharSequence label, Drawable icon) {
        this.packageName = pkg;
        this.label = label;
        this.icon = icon;
    }

    /** Every non-system app that has nativeLibraryDir/libksud.so, sorted by label. */
    static List<SuManagerInfo> load(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        List<SuManagerInfo> out = new ArrayList<>();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            if (!ExploitRunner.hasKsud(ai)) continue;
            out.add(new SuManagerInfo(ai.packageName, pm.getApplicationLabel(ai),
                    pm.getApplicationIcon(ai)));
        }
        out.sort((a, b) -> a.label.toString().compareToIgnoreCase(b.label.toString()));
        return out;
    }

    /** bootstrap reads these from /data/user_de/0/df.root/shared_prefs, so the
     *  selection has to live in the device-protected storage. */
    static SharedPreferences prefs(Context ctx) {
        return ctx.createDeviceProtectedStorageContext()
                .getSharedPreferences(ExploitRunner.PREFS_NAME, Context.MODE_PRIVATE);
    }

    /** Index into {@code managers} of the saved selection, or -1. */
    static int savedIndex(Context ctx, List<SuManagerInfo> managers) {
        String saved = prefs(ctx).getString(ExploitRunner.PREF_SU_MANAGER, null);
        if (saved == null) return -1;
        for (int i = 0; i < managers.size(); i++)
            if (managers.get(i).packageName.equals(saved)) return i;
        prefs(ctx).edit().remove(ExploitRunner.PREF_SU_MANAGER).apply();
        return -1;
    }

    static void save(Context ctx, SuManagerInfo m) {
        prefs(ctx).edit().putString(ExploitRunner.PREF_SU_MANAGER, m.packageName).apply();
    }
}
