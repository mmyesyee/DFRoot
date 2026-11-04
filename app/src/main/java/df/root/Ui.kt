package df.root

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

private val Yellow = Color(0xFFF2C94C)
private val OnYellow = Color(0xFF1C1A00)
private val Red = Color(0xFF8C1C13)
private val OnRed = Color(0xFFFFDAD6)
private val Blue = Color(0xFF1A5FB4)
private val OnBlue = Color(0xFFE3ECFF)
private val Grey = Color(0xFF262626)
private val OnGrey = Color(0xFFE6E1E5)
private val Inactive = Color(0xFF5A5A5A)
private val Good = Color(0xFF8FC79A)

private const val ABOUT = "DFRoot 4.7 · arm32 移植版\n\n" +
        "利用内核页缓存写原语（CVE-2026-43284）加载自定义内核模块，" +
        "不需要解锁 bootloader。\n\n" +
        "原项目 diabl0w/DFRoot，本分支在 32 位用户态（arm64 内核）上工作，" +
        "已在 Xiaomi Watch 2 Pro 验证。\n\n" +
        "致谢：lspromise、DFReroot、DirtyInit"

private enum class Route { Home, Jailbreak, Output, Settings }

/** Everything the screens need, hoisted out of composition so a run survives
 *  navigating away and back. */
private class AppState(val activity: ComponentActivity) {
    val deCtx: Context = activity.createDeviceProtectedStorageContext()

    var managers by mutableStateOf<List<SuManagerInfo>>(emptyList())
    var selected by mutableStateOf(-1)
    var running by mutableStateOf(false)
    var done by mutableStateOf(false)
    var message by mutableStateOf<String?>(null)

    fun refresh() {
        managers = SuManagerInfo.load(activity)
        selected = SuManagerInfo.savedIndex(activity, managers)
        done = File("/dev/dfm6").exists()
    }

    fun select(index: Int) {
        selected = index
        if (index in managers.indices) SuManagerInfo.save(activity, managers[index])
    }

    fun start(scope: CoroutineScope) {
        val index = selected
        if (running || index !in managers.indices) return
        running = true
        message = null
        OutputLog.clear()
        scope.launch {
            val rc = try {
                withContext(Dispatchers.IO) {
                    ExploitRunner.run(deCtx, object : IReporter {
                        override fun report(msg: String) = OutputLog.append(msg)
                    })
                }
            } catch (t: Throwable) {
                OutputLog.append("\nexception: $t\n")
                3
            }
            running = false
            if (rc == 0) done = true
            message = when (rc) {
                0 -> "SUCCESS"
                1 -> "ksud 非零退出"
                2 -> "失败：看输出或 dmesg"
                else -> "打补丁失败"
            }
        }
    }
}

@Composable
fun DfRootApp(activity: ComponentActivity) {
    var route by remember { mutableStateOf(Route.Home) }
    val state = remember { AppState(activity) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(route) { state.refresh() }
    BackHandler(enabled = route != Route.Home) { route = Route.Home }

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        when (route) {
            Route.Home -> HomePager(
                state = state,
                onJailbreak = { route = Route.Jailbreak },
                onOutput = { route = Route.Output },
                onSettings = { route = Route.Settings })

            Route.Jailbreak -> JailbreakScreen(
                state = state,
                scope = scope,
                onOutput = { route = Route.Output })

            Route.Output -> OutputScreen()
            Route.Settings -> SettingsScreen(activity)
        }
    }
}

/* ── pages ───────────────────────────────────────────────────────────────── */

@Composable
private fun HomePager(
    state: AppState,
    onJailbreak: () -> Unit,
    onOutput: () -> Unit,
    onSettings: () -> Unit,
) {
    val pager = rememberPagerState(pageCount = { 2 })
    Column(Modifier.fillMaxSize()) {
        HorizontalPager(state = pager, modifier = Modifier.weight(1f)) { page ->
            if (page == 0) HomePage(state, onJailbreak, onOutput) else MorePage(onSettings)
        }
        Dots(pager.currentPage, 2)
    }
}

@Composable
private fun HomePage(state: AppState, onJailbreak: () -> Unit, onOutput: () -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("主页", color = OnGrey, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(10.dp))
        InfoCard(state)
        Spacer(Modifier.height(10.dp))
        Pill(
            bg = if (state.done) Blue else Red,
            fg = if (state.done) OnBlue else OnRed,
            glyph = "⚡",
            title = if (state.done) "越狱完成" else "点击越狱",
            subtitle = if (state.done) "重启后失效" else "选择管理器并开始",
            onClick = onJailbreak
        )
        Spacer(Modifier.height(10.dp))
        Pill(Grey, OnGrey, "☰", "输出", "查看完整日志", height = 60, onClick = onOutput)
    }
}

@Composable
private fun MorePage(onSettings: () -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("设置与关于", color = OnGrey, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(10.dp))
        Pill(Grey, OnGrey, "⚙", "设置", "启动方式、模块、adbd", onClick = onSettings)
        Spacer(Modifier.height(10.dp))
        AboutCard()
    }
}

@Composable
private fun JailbreakScreen(state: AppState, scope: CoroutineScope, onOutput: () -> Unit) {
    var choosing by remember { mutableStateOf(false) }
    val has = state.selected in state.managers.indices

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("越狱", color = OnGrey, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(10.dp))

        Pill(
            bg = Yellow, fg = OnYellow, glyph = "⚠",
            title = "选择 root 管理器",
            subtitle = if (has) state.managers[state.selected].label.toString() + " · 点击更换"
                       else "未选择 / 点击查看",
            enabled = !state.running,
            onClick = { choosing = true }
        )
        Spacer(Modifier.height(10.dp))

        Pill(
            bg = if (state.done) Blue else Red,
            fg = if (state.done) OnBlue else OnRed,
            glyph = "⚡",
            title = if (state.done) "越狱完成" else "开始越狱",
            subtitle = when {
                state.done -> "重启后失效"
                state.running -> "执行中… 详情见输出"
                has -> "点击开始"
                else -> "请先选择一个 root 管理器"
            },
            enabled = has && !state.done && !state.running,
            onClick = { state.start(scope) }
        )
        Spacer(Modifier.height(10.dp))

        Pill(Grey, OnGrey, "☰", "输出", "查看完整日志", height = 60, onClick = onOutput)

        state.message?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = if (it == "SUCCESS") Good else OnRed, fontSize = 11.sp)
        }
    }

    if (choosing) {
        AlertDialog(
            onDismissRequest = { choosing = false },
            title = { Text("选择 root 管理器") },
            text = {
                Column {
                    state.managers.forEachIndexed { i, m ->
                        Text(
                            m.label.toString(),
                            Modifier.fillMaxWidth()
                                .clickable { state.select(i); choosing = false }
                                .padding(vertical = 10.dp)
                        )
                    }
                    if (state.managers.isEmpty())
                        Text("没有找到带 ksud 的管理器", fontSize = 12.sp)
                }
            },
            confirmButton = {
                TextButton(onClick = { choosing = false }) { Text("取消") }
            }
        )
    }
}

@Composable
private fun OutputScreen() {
    var text by remember { mutableStateOf(OutputLog.get()) }
    val scroll = rememberScrollState()

    LaunchedEffect(Unit) {
        while (true) {
            text = OutputLog.get()
            delay(300)
        }
    }
    LaunchedEffect(text) { scroll.scrollTo(scroll.maxValue) }

    Column(Modifier.fillMaxSize().padding(8.dp)) {
        Text("输出", color = OnGrey, fontSize = 14.sp, fontWeight = FontWeight.Bold)
        Box(Modifier.weight(1f).fillMaxWidth().verticalScroll(scroll)) {
            Text(text, color = OnGrey, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
            TextButton(onClick = { OutputLog.clear(); text = "" }) { Text("清空") }
        }
    }
}

@Composable
private fun SettingsScreen(activity: ComponentActivity) {
    val prefs = SuManagerInfo.prefs(activity)
    var boot by remember { mutableStateOf(bootEnabled(activity)) }
    var soft by remember { mutableStateOf(prefs.getBoolean("soft_reboot", false)) }
    var modules by remember { mutableStateOf(prefs.getBoolean("disable_modules", false)) }
    var adbRoot by remember { mutableStateOf(prefs.getBoolean("adb_root", false)) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 14.dp, vertical = 6.dp)
    ) {
        Text("设置", color = OnGrey, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))

        ToggleRow("开机自动执行", "Start at Boot", boot) {
            boot = it
            setBootEnabled(activity, it)
        }
        ToggleRow("自动软重启", "Auto Soft Reboot", soft) {
            soft = it
            prefs.edit().putBoolean("soft_reboot", it).apply()
        }
        ToggleRow("禁用 KSU 模块", "Disable KSU Modules", modules) {
            modules = it
            prefs.edit().putBoolean("disable_modules", it).apply()
        }
        ToggleRow("成功后 adbd 为 root", "Restart adbd as root", adbRoot) {
            adbRoot = it
            prefs.edit().putBoolean("adb_root", it).apply()
        }
    }
}

/* ── building blocks ─────────────────────────────────────────────────────── */

@Composable
private fun Pill(
    bg: Color,
    fg: Color,
    glyph: String,
    title: String,
    subtitle: String,
    height: Int = 72,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth()
            .height(height.dp)
            .clip(RoundedCornerShape((height / 2).dp))
            .background(if (enabled) bg else bg.copy(alpha = 0.55f))
            .clickable(enabled = enabled) { onClick() }
            .padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(glyph, color = fg, fontSize = 20.sp, modifier = Modifier.width(34.dp))
        Column(Modifier.weight(1f)) {
            Text(title, color = fg, fontSize = 15.sp, fontWeight = FontWeight.Bold, maxLines = 1)
            Text(subtitle, color = fg, fontSize = 12.sp, maxLines = 1)
        }
    }
}

@Composable
private fun InfoCard(state: AppState) {
    val su = if (state.selected in state.managers.indices)
        state.managers[state.selected].label.toString() else "未选择"
    val status = when {
        state.done -> "已越狱（重启后失效）"
        File("/dev/df").exists() -> "已执行，未见结果"
        else -> "未执行"
    }
    val abi = if (Build.SUPPORTED_ABIS.isNotEmpty()) Build.SUPPORTED_ABIS[0] else "?"

    val text = buildString {
        appendLine("型号   ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("系统   Android ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})")
        appendLine("补丁   ${Build.VERSION.SECURITY_PATCH}")
        appendLine("内核   ${System.getProperty("os.version", "?")}")
        appendLine("ABI    $abi")
        appendLine("管理器 $su")
        append("状态   $status")
    }

    Box(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(Grey)
            .padding(horizontal = 14.dp, vertical = 10.dp)
    ) {
        Text(text, color = OnGrey, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun AboutCard() {
    var show by remember { mutableStateOf(false) }
    Pill(Grey, OnGrey, "ⓘ", "关于", "版本与致谢") { show = true }
    if (show) {
        AlertDialog(
            onDismissRequest = { show = false },
            title = { Text("关于 DFRoot") },
            text = { Text(ABOUT) },
            confirmButton = { TextButton(onClick = { show = false }) { Text("好") } }
        )
    }
}

@Composable
private fun Dots(current: Int, count: Int) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.Center
    ) {
        repeat(count) { i ->
            Box(
                Modifier.padding(horizontal = 3.dp).size(6.dp).clip(CircleShape)
                    .background(if (i == current) Color.White else Inactive)
            )
        }
    }
}

@Composable
private fun ToggleRow(title: String, sub: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, color = OnGrey, fontSize = 13.sp)
            Text(sub, color = Inactive, fontSize = 10.sp, maxLines = 1)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

private fun bootEnabled(ctx: Context): Boolean =
    ctx.packageManager.getComponentEnabledSetting(ComponentName(ctx, BootReceiver::class.java)) ==
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED

private fun setBootEnabled(ctx: Context, enabled: Boolean) {
    ctx.packageManager.setComponentEnabledSetting(
        ComponentName(ctx, BootReceiver::class.java),
        if (enabled) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
        PackageManager.DONT_KILL_APP
    )
}
