package df.root;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
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
 * Two pages, watch sized, Material 3.
 *
 * page 0 - this watch: what it is, and the three actions
 * page 1 - settings and about
 *
 * Horizontal fling toggles between them (the device has no action bar and a
 * ViewPager dependency is not worth it for two pages).
 */
public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private MaterialCardView cardManager;
    private MaterialCardView cardRun;
    private TextView tvManagerTitle;
    private TextView tvManagerSub;
    private TextView tvRunTitle;
    private TextView tvRunSub;
    private TextView tvDeviceInfo;
    private View pageMain;
    private View pageMore;
    private View dot0;
    private View dot1;

    private Context mDeCtx;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private final List<SuManagerEntry> mEntries = new ArrayList<>();
    private int mValidSuManagerPos = 0;
    private boolean mRunning = false;
    private int mPage = 0;
    private GestureDetector mGesture;

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
        tvDeviceInfo = findViewById(R.id.tvDeviceInfo);
        pageMain = findViewById(R.id.pageMain);
        pageMore = findViewById(R.id.pageMore);
        dot0 = findViewById(R.id.dot0);
        dot1 = findViewById(R.id.dot1);
        MaterialCardView cardOutput = findViewById(R.id.cardOutput);

        loadManagers();

        mGesture = new GestureDetector(this, new GestureDetector.SimpleOnGestureListener() {
            @Override
            public boolean onFling(MotionEvent e1, MotionEvent e2, float vx, float vy) {
                if (e1 == null || e2 == null) return false;
                float dx = e2.getX() - e1.getX();
                float dy = e2.getY() - e1.getY();
                if (Math.abs(dx) < 48 || Math.abs(dx) < Math.abs(dy)) return false;
                showPage(mPage == 0 ? 1 : 0);
                return true;
            }
        });

        cardManager.setOnClickListener(v -> {
            if (!mRunning) showManagerChooser();
        });
        cardOutput.setOnClickListener(v -> startActivity(new Intent(this, OutputActivity.class)));
        cardRun.setOnClickListener(v -> {
            if (mRunning) return;
            mRunning = true;
            OutputLog.clear();
            updateCards();
            mExec.execute(this::runExploit);
        });
        findViewById(R.id.cardSettings).setOnClickListener(
                v -> startActivity(new Intent(this, SettingsActivity.class)));
        findViewById(R.id.cardAbout).setOnClickListener(v ->
                new MaterialAlertDialogBuilder(this)
                        .setTitle(R.string.about_title)
                        .setMessage(R.string.about_body)
                        .setPositiveButton(android.R.string.ok, null)
                        .show());

        updateCards();
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (mGesture != null) mGesture.onTouchEvent(ev);
        return super.dispatchTouchEvent(ev);
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateCards();
    }

    private void showPage(int p) {
        if (p == mPage) return;
        mPage = p;
        View in = p == 0 ? pageMain : pageMore;
        View out = p == 0 ? pageMore : pageMain;
        in.setVisibility(View.VISIBLE);
        in.setAlpha(0f);
        in.setTranslationX(p == 0 ? -48f : 48f);
        in.animate().alpha(1f).translationX(0f).setDuration(160).start();
        out.animate().alpha(0f).translationX(p == 0 ? 48f : -48f).setDuration(120)
                .withEndAction(() -> out.setVisibility(View.GONE)).start();
        dot0.setBackgroundResource(p == 0 ? R.drawable.dot_active : R.drawable.dot_inactive);
        dot1.setBackgroundResource(p == 1 ? R.drawable.dot_active : R.drawable.dot_inactive);
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
        boolean restored = false;
        for (int i = 1; i < mEntries.size(); i++) {
            if (mEntries.get(i).packageName.equals(saved)) {
                mValidSuManagerPos = i;
                restored = true;
                break;
            }
        }
        if (!restored && saved != null)
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

        refreshInfo(hasManager, hooked);
    }

    private void refreshInfo(boolean hasManager, boolean hooked) {
        String abi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "?";
        String su = hasManager ? mEntries.get(mValidSuManagerPos).label.toString()
                              : getString(R.string.card_manager_none);
        String state = hooked ? "本次已执行" : (mRunning ? "执行中…" : "未执行");

        StringBuilder sb = new StringBuilder();
        sb.append("型号   ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append('\n');
        sb.append("系统   Android ").append(Build.VERSION.RELEASE)
          .append(" (SDK ").append(Build.VERSION.SDK_INT).append(")\n");
        sb.append("补丁   ").append(Build.VERSION.SECURITY_PATCH).append('\n');
        sb.append("内核   ").append(System.getProperty("os.version", "?")).append('\n');
        sb.append("ABI    ").append(abi).append('\n');
        sb.append("管理器 ").append(su).append('\n');
        sb.append("状态   ").append(state);
        tvDeviceInfo.setText(sb);
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
