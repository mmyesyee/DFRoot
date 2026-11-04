package df.root;

import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Bundle;

import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.SwitchPreferenceCompat;

public class SettingsFragment extends PreferenceFragmentCompat {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.preferences, rootKey);

        Context ctx = getActivity();
        SharedPreferences dePrefs = ctx.createDeviceProtectedStorageContext()
                .getSharedPreferences(ExploitRunner.PREFS_NAME, Context.MODE_PRIVATE);

        ComponentName bootReceiver = new ComponentName(ctx, BootReceiver.class);
        SwitchPreferenceCompat bootPref = findPreference("boot_start");
        bootPref.setPersistent(false);
        int state = ctx.getPackageManager().getComponentEnabledSetting(bootReceiver);
        bootPref.setChecked(state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED);
        bootPref.setOnPreferenceChangeListener((pref, value) -> {
            ctx.getPackageManager().setComponentEnabledSetting(bootReceiver,
                    (Boolean) value ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                                    : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP);
            return true;
        });

        bindSwitch(dePrefs, "soft_reboot");
        bindSwitch(dePrefs, "disable_modules");
        bindSwitch(dePrefs, "adb_root");
    }

    private void bindSwitch(SharedPreferences prefs, String key) {
        SwitchPreferenceCompat pref = findPreference(key);
        pref.setPersistent(false);
        pref.setChecked(prefs.getBoolean(key, false));
        pref.setOnPreferenceChangeListener((p, value) -> {
            prefs.edit().putBoolean(key, (Boolean) value).apply();
            return true;
        });
    }
}
