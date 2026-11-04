package df.root;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.io.File;
import java.util.List;

/**
 * Two pages, watch sized, Material 3.
 *
 * page 0 - this watch: what it is, plus one red card that opens the jailbreak
 *          sub page
 * page 1 - settings and about
 *
 * Horizontal fling toggles the pages (the device has no action bar, and a
 * ViewPager dependency is not worth it for two pages).
 */
public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private TextView tvDeviceInfo;
    private View pageMain;
    private View pageMore;
    private View dot0;
    private View dot1;

    private Context mDeCtx;
    private final Handler mMain = new Handler(Looper.getMainLooper());
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

        tvDeviceInfo = findViewById(R.id.tvDeviceInfo);
        pageMain = findViewById(R.id.pageMain);
        pageMore = findViewById(R.id.pageMore);
        dot0 = findViewById(R.id.dot0);
        dot1 = findViewById(R.id.dot1);

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

        findViewById(R.id.cardJailbreak).setOnClickListener(
                v -> startActivity(new Intent(this, JailbreakActivity.class)));
        findViewById(R.id.cardSettings).setOnClickListener(
                v -> startActivity(new Intent(this, SettingsActivity.class)));
        findViewById(R.id.cardAbout).setOnClickListener(v ->
                new MaterialAlertDialogBuilder(this)
                        .setTitle(R.string.about_title)
                        .setMessage(R.string.about_body)
                        .setPositiveButton(android.R.string.ok, null)
                        .show());

        refreshInfo();
        mMain.postDelayed(this::refreshInfo, 1200);
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (mGesture != null) mGesture.onTouchEvent(ev);
        return super.dispatchTouchEvent(ev);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshInfo();
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

    private void refreshInfo() {
        List<SuManagerInfo> managers = SuManagerInfo.load(this);
        int idx = SuManagerInfo.savedIndex(this, managers);
        String su = idx >= 0 ? managers.get(idx).label.toString()
                             : getString(R.string.card_manager_none);
        boolean hooked = new File("/dev/df").exists();
        String abi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "?";

        StringBuilder sb = new StringBuilder();
        sb.append("型号   ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append('\n');
        sb.append("系统   Android ").append(Build.VERSION.RELEASE)
          .append(" (SDK ").append(Build.VERSION.SDK_INT).append(")\n");
        sb.append("补丁   ").append(Build.VERSION.SECURITY_PATCH).append('\n');
        sb.append("内核   ").append(System.getProperty("os.version", "?")).append('\n');
        sb.append("ABI    ").append(abi).append('\n');
        sb.append("管理器 ").append(su).append('\n');
        sb.append("状态   ").append(hooked ? "本次已执行" : "未执行");
        tvDeviceInfo.setText(sb);
    }
}
