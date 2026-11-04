package df.root;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Full-screen view of the exploit output. The main page has to share a 466x466
 * screen with the spinner and the button, which leaves very little room for the
 * log - this page gets all of it.
 */
public class OutputActivity extends Activity {

    private TextView mText;
    private ScrollView mScroll;
    private final Handler mHandler = new Handler(Looper.getMainLooper());

    private final Runnable mRefresh = new Runnable() {
        @Override
        public void run() {
            String s = OutputLog.get();
            if (!s.equals(mText.getText().toString())) {
                mText.setText(s);
                mScroll.post(() -> mScroll.fullScroll(View.FOCUS_DOWN));
            }
            mHandler.postDelayed(this, 400);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_output);
        mText = findViewById(R.id.outputTextFull);
        mScroll = findViewById(R.id.outputScrollFull);
        mText.setText(OutputLog.get());
        mScroll.post(() -> mScroll.fullScroll(View.FOCUS_DOWN));
    }

    @Override
    protected void onResume() {
        super.onResume();
        mHandler.post(mRefresh);
    }

    @Override
    protected void onPause() {
        super.onPause();
        mHandler.removeCallbacks(mRefresh);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.output_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_clear_output) {
            OutputLog.clear();
            mText.setText("");
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
