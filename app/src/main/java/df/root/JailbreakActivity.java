package df.root;

import android.content.Context;
import android.content.Intent;
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
 * The jailbreak sub page: pick the root manager on top, start the exploit below.
 * Kept separate from the home page so the action cannot be hit by accident.
 */
public class JailbreakActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private MaterialCardView cardManager;
    private MaterialCardView cardStart;
    private TextView tvPickSub;
    private TextView tvStartSub;

    private final List<SuManagerInfo> mManagers = new ArrayList<>();
    private int mSelected = -1;
    private boolean mRunning = false;

    private Context mDeCtx;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        OutputLog.append(msg);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mDeCtx = createDeviceProtectedStorageContext();
        setContentView(R.layout.activity_jailbreak);

        cardManager = findViewById(R.id.cardManager);
        cardStart = findViewById(R.id.cardStart);
        tvPickSub = findViewById(R.id.tvPickSub);
        tvStartSub = findViewById(R.id.tvStartSub);

        mManagers.addAll(SuManagerInfo.load(this));
        mSelected = SuManagerInfo.savedIndex(this, mManagers);

        cardManager.setOnClickListener(v -> {
            if (!mRunning) chooseManager();
        });
        cardStart.setOnClickListener(v -> start());
        findViewById(R.id.cardOutput).setOnClickListener(
                v -> startActivity(new Intent(this, OutputActivity.class)));

        updateUi();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateUi();
    }

    private void chooseManager() {
        if (mManagers.isEmpty()) {
            Toast.makeText(this, R.string.no_manager, Toast.LENGTH_LONG).show();
            return;
        }
        CharSequence[] labels = new CharSequence[mManagers.size()];
        for (int i = 0; i < mManagers.size(); i++)
            labels[i] = mManagers.get(i).label;

        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.card_pick_manager)
                .setItems(labels, (d, which) -> {
                    mSelected = which;
                    SuManagerInfo.save(this, mManagers.get(which));
                    updateUi();
                })
                .show();
    }

    private void start() {
        if (mRunning || mSelected < 0 || mSelected >= mManagers.size()) return;
        mRunning = true;
        OutputLog.clear();
        updateUi();
        mExec.execute(this::run);
    }

    private void run() {
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
                updateUi();
            });
        }
    }

    private void updateUi() {
        boolean has = mSelected >= 0 && mSelected < mManagers.size();
        boolean hooked = new File("/dev/df").exists();

        tvPickSub.setText(has
                ? mManagers.get(mSelected).label + "  ·  点击更换"
                : getString(R.string.card_pick_manager_none));

        if (hooked) {
            tvStartSub.setText(R.string.card_start_done);
        } else if (mRunning) {
            tvStartSub.setText(R.string.card_start_busy);
        } else if (has) {
            tvStartSub.setText(R.string.card_start_ready);
        } else {
            tvStartSub.setText(R.string.card_start_blocked);
        }

        boolean enabled = has && !hooked && !mRunning;
        cardStart.setEnabled(enabled);
        cardStart.setAlpha(enabled ? 1f : 0.55f);
        cardManager.setEnabled(!mRunning);
    }
}
