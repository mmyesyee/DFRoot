package df.root

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i("dfroot", "MainActivity onCreate")
        setContent {
            Log.i("dfroot", "compose content")
            DfRootApp(this)
        }
    }
}
