package df.root;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.card.MaterialCardView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Watch-sized, Material 3 home screen: a stack of rounded cards, one per thing
 * the user can do. The device has no action bar, so everything is reachable by
 * tapping a card.
 */
public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private MaterialCardView cardManager;
    private MaterialCardView cardRun;
    private TextView tvManagerTitle;
    private TextView tvManagerSub;
    private TextView tvRunTitle;
    private TextView tvRunSub;

    private Context mDeCtx;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private final List<SuManagerEntry> mEntries = new ArrayList<>();
    private int mValidSuManagerPos = 0;
    private boolean mRunning = false;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        OutputLog.append(msg);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mDeCtx = createDeviceProtectedStorageContext();
        setContentView(R.layout.activity_main);

        cardManager = findViewById(R.id.cardManager);
        cardRun = findViewById(R.id.cardRun);
        tvManagerTitle = findViewById(R.id.tvManagerTitle);
        tvManagerSub = findViewById(R.id.tvManagerSub);
        tvRunTitle = findViewById(R.id.tvRunTitle);
        tvRunSub = findViewById(R.id.tvRunSub);
        MaterialCardView cardOutput = findViewById(R.id.cardOutput);

        loadManagers();

        cardManager.setOnClickListener(v -> {
            if (!mRunning) showManagerChooser();
        });
        cardOutput.setOnClickListener(v -> startActivity(new Intent(this, OutputActivity.class)));
        findViewById(R.id.btnSettings).setOnClickListener(
                v -> startActivity(new Intent(this, SettingsActivity.class)));
        cardRun.setOnClickListener(v -> {
            if (mRunning) return;
            mRunning = true;
            OutputLog.clear();
            updateCards();
            mExec.execute(this::runExploit);
        });

        updateCards();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateCards();
    }

    private void loadManagers() {
        mEntries.clear();
        mEntries.add(new SuManagerEntry(null, getString(R.string.card_manager_none), null));

        PackageManager pm = getPackageManager();
        List<SuManagerEntry> found = new ArrayList<>();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            if (!ExploitRunner.hasKsud(ai)) continue;
            found.add(new SuManagerEntry(ai.packageName,
                    pm.getApplicationLabel(ai), pm.getApplicationIcon(ai)));
        }
        found.sort((a, b) -> a.label.toString().compareToIgnoreCase(b.label.toString()));
        mEntries.addAll(found);

        SharedPreferences prefs = mDeCtx.getSharedPreferences(ExploitRunner.PREFS_NAME, Context.MODE_PRIVATE);
        String saved = prefs.getString(ExploitRunner.PREF_SU_MANAGER, null);
        boolean found2 = false;
        for (int i = 1; i < mEntries.size(); i++) {
            if (mEntries.get(i).packageName.equals(saved)) {
                mValidSuManagerPos = i;
                found2 = true;
                break;
            }
        }
        if (!found2 && saved != null)
            prefs.edit().remove(ExploitRunner.PREF_SU_MANAGER).apply();
    }

    private void showManagerChooser() {
        if (mEntries.size() <= 1) {
            Toast.makeText(this, R.string.no_manager, Toast.LENGTH_LONG).show();
            return;
        }
        CharSequence[] labels = new CharSequence[mEntries.size() - 1];
        for (int i = 1; i < mEntries.size(); i++)
            labels[i - 1] = mEntries.get(i).label;

        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.chooser_title)
                .setItems(labels, (d, which) -> {
                    int pos = which + 1;
                    mValidSuManagerPos = pos;
                    mDeCtx.getSharedPreferences(ExploitRunner.PREFS_NAME, Context.MODE_PRIVATE)
                            .edit()
                            .putString(ExploitRunner.PREF_SU_MANAGER, mEntries.get(pos).packageName)
                            .apply();
                    updateCards();
                })
                .show();
    }

    private void updateCards() {
        boolean hasManager = mValidSuManagerPos >= 1 && mValidSuManagerPos < mEntries.size();
        if (hasManager) {
            tvManagerTitle.setText(mEntries.get(mValidSuManagerPos).label);
            tvManagerSub.setText(R.string.card_manager_change);
        } else {
            tvManagerTitle.setText(R.string.card_manager_none);
            tvManagerSub.setText(R.string.card_manager_tap);
        }

        boolean hooked = new File("/dev/df").exists();
        if (hooked) {
            tvRunTitle.setText(R.string.card_run_hooked);
            tvRunSub.setText(R.string.card_run_hooked_sub);
        } else if (mRunning) {
            tvRunTitle.setText(R.string.card_run_busy);
            tvRunSub.setText(R.string.card_run_busy_sub);
        } else if (hasManager) {
            tvRunTitle.setText(R.string.card_run_ready);
            tvRunSub.setText(R.string.card_run_ready_sub);
        } else {
            tvRunTitle.setText(R.string.card_run_none);
            tvRunSub.setText(R.string.card_run_none_sub);
        }

        boolean enabled = hasManager && !hooked && !mRunning;
        cardRun.setEnabled(enabled);
        cardRun.setAlpha(enabled ? 1f : 0.55f);
        cardManager.setEnabled(!mRunning);
    }

    private void runExploit() {
        try {
            int rc = ExploitRunner.run(mDeCtx, this);
            String msg = rc == 0 ? "DFRoot: SUCCESS"
                       : rc == 1 ? "DFRoot: Error - ksud nonzero exit"
                       : rc == 2 ? "DFRoot: Error - check logcat & dmesg"
                       : "DFRoot: Error - failed to patch files";
            mMain.post(() -> Toast.makeText(this, msg, Toast.LENGTH_LONG).show());
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\nexception: " + e + "\n");
        } finally {
            mMain.post(() -> {
                mRunning = false;
                updateCards();
            });
        }
    }

    private static class SuManagerEntry {
        final String packageName;
        final CharSequence label;
        final Drawable icon;

        SuManagerEntry(String pkg, CharSequence label, Drawable icon) {
            this.packageName = pkg;
            this.label = label;
            this.icon = icon;
        }
    }
}
