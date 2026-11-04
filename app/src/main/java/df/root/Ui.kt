package df.root

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
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
import java.io.FileInputStream

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

private const val TAG = "dfroot"

private const val ABOUT = "DFRoot 4.7 · arm32 移植版\n\n" +
        "利用内核页缓存写原语（CVE-2026-43284）加载自定义内核模块，" +
        "不需要解锁 bootloader。\n\n" +
        "原项目 diabl0w/DFRoot，本分支在 32 位用户态（arm64 内核）上工作，" +
        "已在 Xiaomi Watch 2 Pro 验证。\n\n" +
        "致谢：lspromise、DFReroot、DirtyInit"

private enum class KoSlot(val label: String, val file: String, val override: String, val note: String) {
    Dfroot("dfroot.ko", "ko", "dfroot_custom.ko", "越狱用的内核模块 · APK 内置，按 KMI 选"),
    Kernelsu("kernelsu.ko", "kernelsu.ko", "kernelsu_custom.ko", "管理器的内核模块 · 从管理器 APK 抽取"),
}

private enum class Route { Home, Jailbreak, Managers, Ko, KoDfroot, KoKernelsu, Browser, Output, Settings }

/** Everything the screens need, hoisted out of composition so a run survives
 *  navigating away and back. */
private class AppState(val activity: ComponentActivity) {
    val deCtx: Context = activity.createDeviceProtectedStorageContext()

    var managers by mutableStateOf<List<SuManagerInfo>>(emptyList())
    var selected by mutableStateOf(-1)
    var running by mutableStateOf(false)
    var done by mutableStateOf(false)
    var message by mutableStateOf<String?>(null)
    var koMessage by mutableStateOf<String?>(null)
    var koSlot by mutableStateOf(KoSlot.Dfroot)

    private fun dataDir() = deCtx.filesDir.parentFile
    fun koDefault(slot: KoSlot) = File(dataDir(), slot.file)
    fun koOverride(slot: KoSlot) = File(dataDir(), slot.override)

    /** Pick a module for the slot currently being edited; empty means default. */
    fun pickKo(src: File): String = try {
        val dst = koOverride(koSlot)
        src.inputStream().use { i -> dst.outputStream().use { o -> i.copyTo(o) } }
        "${koSlot.label}: 已设为自定义（${dst.length()} 字节 · ${elfArch(dst)}），下次越狱生效"
    } catch (t: Throwable) {
        "复制失败: ${t.message}"
    }

    fun clearKo(slot: KoSlot): String = try {
        val f = koOverride(slot)
        val gone = !f.exists() || f.delete()
        if (gone) "${slot.label}: 已恢复默认" else "${slot.label}: 删除失败"
    } catch (t: Throwable) {
        "删除失败: ${t.message}"
    }

    fun refresh() {
        managers = SuManagerInfo.load(activity)
        selected = SuManagerInfo.savedIndex(activity, managers)
        done = File("/dev/dfm6").exists()
    }

    fun note(msg: String) {
        message = msg
    }

    fun select(index: Int) {
        selected = index
        if (index in managers.indices) SuManagerInfo.save(activity, managers[index])
    }

    /** Copy a picked .ko into custom.ko, which bootstrap loads on the next run. */
    fun pickCustomKo(src: File): String = try {
        val dst = File(deCtx.filesDir.parentFile, "custom.ko")
        src.inputStream().use { i -> dst.outputStream().use { o -> i.copyTo(o) } }
        "已选为 custom.ko（${dst.length()} 字节），下次越狱时加载"
    } catch (t: Throwable) {
        "复制失败: ${t.message}"
    }

    fun start(scope: CoroutineScope) {
        val index = selected
        Log.i(TAG, "start() selected=$index count=${managers.size} running=$running")
        if (running || index !in managers.indices) return
        running = true
        message = null
        OutputLog.clear()
        scope.launch {
            val rc = try {
                withContext(Dispatchers.IO) {
                    ExploitRunner.run(deCtx, object : IReporter {
                        /* both: the output page reads OutputLog, adb logcat reads
                         * the tag - losing one of them makes debugging blind */
                        override fun report(msg: String) {
                            Log.i(TAG, msg.trim())
                            OutputLog.append(msg)
                        }
                    })
                }
            } catch (t: Throwable) {
                OutputLog.append("\nexception: $t\n")
                3
            }
            running = false
            if (rc == 0) done = true
            if (OutputLog.get().isEmpty())
                OutputLog.append("no output from the exploit (rc=$rc)\n")
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

    LaunchedEffect(route) {
        state.refresh()
        Log.i(TAG, "route=$route managers=${state.managers.size} selected=${state.selected} done=${state.done}")
    }
    BackHandler(enabled = route != Route.Home) {
        route = if (route == Route.Managers) Route.Jailbreak else Route.Home
    }

    /* once it is rooted there is nothing to do on the jailbreak pages */
    LaunchedEffect(state.done) {
        if (state.done && (route == Route.Jailbreak || route == Route.Managers))
            route = Route.Home
    }

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
                onPickManagers = { route = Route.Managers },
                onKo = { route = Route.Ko },
                onOutput = { route = Route.Output })

            Route.Managers -> ManagerScreen(
                state = state,
                onPicked = { route = Route.Jailbreak })

            Route.Ko -> KoMenuScreen(
                activity = activity,
                onSlot = { slot ->
                    route = if (slot == KoSlot.Dfroot) Route.KoDfroot else Route.KoKernelsu
                })

            Route.KoDfroot -> KoSlotScreen(
                activity = activity,
                slot = KoSlot.Dfroot,
                message = state.koMessage,
                onBrowser = { state.koSlot = it; route = Route.Browser })

            Route.KoKernelsu -> KoSlotScreen(
                activity = activity,
                slot = KoSlot.Kernelsu,
                message = state.koMessage,
                onBrowser = { state.koSlot = it; route = Route.Browser })

            Route.Browser -> BrowserScreen(
                activity = activity,
                onPicked = { file ->
                    state.koMessage = state.pickKo(file)
                    route = if (state.koSlot == KoSlot.Dfroot) Route.KoDfroot else Route.KoKernelsu
                })

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
        Pill(
            bg = if (state.done) Blue else Red,
            fg = if (state.done) OnBlue else OnRed,
            glyph = if (state.done) "✓" else "⚡",
            title = if (state.done) "越狱完成" else "点击越狱",
            subtitle = if (state.done) "重启后可再次越狱" else "选择管理器并开始",
            /* already rooted this boot: nothing to open */
            enabled = !state.done,
            onClick = onJailbreak
        )
        Spacer(Modifier.height(10.dp))
        InfoCard(state)
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
private fun JailbreakScreen(
    state: AppState,
    scope: CoroutineScope,
    onPickManagers: () -> Unit,
    onKo: () -> Unit,
    onOutput: () -> Unit,
) {
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
            onClick = onPickManagers
        )
        Spacer(Modifier.height(10.dp))

        val canStart = has && !state.done && !state.running
        Pill(
            bg = if (state.done) Blue else Red,
            fg = if (state.done) OnBlue else OnRed,
            glyph = "⚡",
            title = if (state.done) "越狱完成" else "开始越狱",
            subtitle = when {
                state.done -> "已越狱 · 重启后可再次执行"
                state.running -> "执行中… 详情见输出"
                has -> "点击开始"
                else -> "请先选择一个 root 管理器"
            },
            /* always tappable: a dead card looks broken, an explanation does not */
            enabled = true,
            alpha = if (canStart) 1f else 0.65f,
            onClick = {
                when {
                    state.running -> state.note("正在执行，请看输出")
                    state.done -> state.note("本次已经越狱，重启手表后才能再执行")
                    !has -> state.note("请先选择一个 root 管理器")
                    else -> state.start(scope)
                }
            }
        )
        Spacer(Modifier.height(10.dp))
        Pill(Grey, OnGrey, "⬇", "加载自定义 KO", "查看/更换要加载的内核模块",
             height = 60, onClick = onKo)

        Spacer(Modifier.height(10.dp))
        Pill(Grey, OnGrey, "☰", "输出", "查看完整日志", height = 60, onClick = onOutput)

        state.message?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = if (it == "SUCCESS") Good else OnRed, fontSize = 11.sp)
        }
    }

}

@Composable
private fun ManagerScreen(state: AppState, onPicked: () -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("选择管理器", color = OnGrey, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(10.dp))

        if (state.managers.isEmpty()) {
            Text(
                "没有找到带 ksud 的管理器",
                color = Inactive, fontSize = 12.sp,
                modifier = Modifier.padding(top = 20.dp)
            )
            return@Column
        }

        state.managers.forEachIndexed { i, m ->
            val picked = i == state.selected
            Pill(
                bg = if (picked) Yellow else Grey,
                fg = if (picked) OnYellow else OnGrey,
                glyph = if (picked) "✓" else "⚙",
                title = m.label.toString(),
                subtitle = m.packageName,
                height = 64,
                onClick = { state.select(i); onPicked() }
            )
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun KoMenuScreen(activity: ComponentActivity, onSlot: (KoSlot) -> Unit) {
    val dataDir = activity.createDeviceProtectedStorageContext().filesDir.parentFile
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("内核模块", color = OnGrey, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        Text("不选自定义就用默认", color = Inactive, fontSize = 10.sp)
        Spacer(Modifier.height(10.dp))

        KoSlot.entries.forEach { slot ->
            val ovr = File(dataDir, slot.override)
            val def = File(dataDir, slot.file)
            val custom = ovr.exists()
            Pill(
                bg = if (custom) Yellow else Grey,
                fg = if (custom) OnYellow else OnGrey,
                glyph = if (custom) "✦" else "⚙",
                title = slot.label,
                subtitle = if (custom) "自定义 · ${describeElf(ovr)}" else "默认 · ${describeElf(def)}",
                onClick = { onSlot(slot) }
            )
            Spacer(Modifier.height(10.dp))
        }
    }
}

@Composable
private fun KoSlotScreen(
    activity: ComponentActivity,
    slot: KoSlot,
    message: String?,
    onBrowser: (KoSlot) -> Unit,
) {
    val dataDir = activity.createDeviceProtectedStorageContext().filesDir.parentFile
    val def = File(dataDir, slot.file)
    val ovr = File(dataDir, slot.override)
    var info by remember { mutableStateOf<String?>(null) }
    var custom by remember { mutableStateOf(ovr.exists()) }
    val scope = rememberCoroutineScope()

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            info = try {
                withContext(Dispatchers.IO) {
                    activity.contentResolver.openInputStream(uri).use { input ->
                        requireNotNull(input) { "openInputStream 返回 null" }
                        ovr.outputStream().use { out -> input.copyTo(out) }
                    }
                }
                custom = ovr.exists()
                "已设为自定义（${ovr.length()} 字节 · ${elfArch(ovr)}），下次越狱生效"
            } catch (t: Throwable) {
                "复制失败: ${t.message}"
            }
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Text(slot.label, color = OnGrey, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        Text(slot.note, color = Inactive, fontSize = 10.sp)
        Spacer(Modifier.height(10.dp))

        KoRow(if (custom) "当前：自定义" else "当前：默认",
              if (custom) ovr.absolutePath else def.absolutePath,
              describeElf(if (custom) ovr else def))
        Spacer(Modifier.height(8.dp))

        KoRow("默认文件", def.absolutePath, describeElf(def))
        if (custom) {
            Spacer(Modifier.height(8.dp))
            KoRow("自定义覆盖", ovr.absolutePath, describeElf(ovr))
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = {
                info = try {
                    if (ovr.delete() || !ovr.exists()) { custom = ovr.exists(); "已恢复默认" }
                    else "删除失败"
                } catch (t: Throwable) {
                    "删除失败: ${t.message}"
                }
            }) { Text("恢复默认") }
        }

        Spacer(Modifier.height(10.dp))
        Pill(Grey, OnGrey, "📂", "从文件管理器选择…", "系统选择器（部分表不支持）",
             height = 56) { picker.launch(arrayOf("*/*")) }
        Spacer(Modifier.height(8.dp))
        Pill(Grey, OnGrey, "🗂", "浏览本机目录…", "内置文件浏览器", height = 56,
             onClick = { onBrowser(slot) })

        (info ?: message)?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = Good, fontSize = 10.sp)
        }
    }
}

@Composable
private fun KoRow(title: String, sub: String, value: String) {
    Box(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Grey)
            .padding(horizontal = 14.dp, vertical = 8.dp)
    ) {
        Column {
            Text(title, color = OnGrey, fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Text(sub, color = Inactive, fontSize = 9.sp, maxLines = 2)
            Text(value, color = OnGrey, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
        }
    }
}

@Composable
private fun BrowserScreen(activity: ComponentActivity, onPicked: (File) -> Unit) {
    val starts = remember {
        listOfNotNull(
            activity.createDeviceProtectedStorageContext().filesDir.parentFile,
            activity.getExternalFilesDir(null),
            File("/sdcard/Android/data/df.root/files"),
            File("/sdcard/Download"),
            File("/sdcard"),
            File("/")
        ).distinctBy { it.absolutePath }
    }
    var dir by remember { mutableStateOf(starts.firstOrNull() ?: File("/")) }
    var rows by remember { mutableStateOf<List<File>>(emptyList()) }
    var err by remember { mutableStateOf<String?>(null) }
    var tick by remember { mutableStateOf(0) }

    LaunchedEffect(dir, tick) {
        val (list, e) = withContext(Dispatchers.IO) {
            val f = dir.listFiles()
            if (f == null) Pair(emptyList<File>(), "无法读取（scoped storage 或权限不足）")
            else Pair(f.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() })), null)
        }
        rows = list
        err = e
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 8.dp, vertical = 4.dp)) {
        Text("选择 .ko", color = OnGrey, fontSize = 15.sp, fontWeight = FontWeight.Bold)
        Text(dir.absolutePath, color = Inactive, fontSize = 9.sp,
             fontFamily = FontFamily.Monospace, maxLines = 2)

        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            starts.take(4).forEach { r ->
                TextButton(onClick = { dir = r }) {
                    Text(r.name.ifEmpty { "/" }, fontSize = 9.sp)
                }
            }
        }

        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            TextButton(onClick = {
                dir.parentFile?.let { if (it.canRead()) dir = it }
            }) { Text("上级", fontSize = 10.sp) }
            TextButton(onClick = { tick++ }) { Text("刷新", fontSize = 10.sp) }
        }

        err?.let { Text(it, color = OnRed, fontSize = 9.sp) }

        LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
            items(rows, key = { it.absolutePath }) { f ->
                val isDir = f.isDirectory
                /* kernelsu.ko ships as libkernelsu.so, so both suffixes count */
                val isKo = f.name.endsWith(".ko") || f.name.endsWith(".so")
                Row(
                    Modifier.fillMaxWidth()
                        .clickable(enabled = isDir || isKo) {
                            if (isDir) dir = f else onPicked(f)
                        }
                        .padding(vertical = 8.dp, horizontal = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        when {
                            isDir -> "📁"
                            isKo -> "⬇"
                            else -> "·"
                        },
                        fontSize = 13.sp, modifier = Modifier.width(22.dp)
                    )
                    Column(Modifier.weight(1f)) {
                        Text(
                            f.name + if (isDir) "/" else "",
                            color = if (isDir || isKo) OnGrey else Inactive,
                            fontSize = 12.sp, maxLines = 1
                        )
                        if (isKo) Text(describeElf(f), color = Inactive, fontSize = 9.sp,
                                       fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }
    }
}

private fun elfArch(f: File): String {
    val head = ByteArray(20)
    val n = try {
        FileInputStream(f).use { it.read(head) }
    } catch (t: Throwable) {
        -1
    }
    if (n != head.size) return "未知架构"
    val machine = (head[18].toInt() and 0xff) or ((head[19].toInt() and 0xff) shl 8)
    return when (machine) {
        183 -> "aarch64"
        40 -> "arm32"
        else -> "machine=$machine"
    }
}

private fun describeElf(f: File): String {
    if (!f.exists()) return "不存在"
    return "${f.length()} 字节 · ${elfArch(f)}"
}

@Composable
private fun OutputScreen() {
    var text by remember { mutableStateOf(OutputLog.get()) }
    var info by remember { mutableStateOf<String?>(null) }
    val scroll = rememberScrollState()
    val clipboard = LocalClipboardManager.current
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

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

        info?.let {
            Text(it, color = Good, fontSize = 9.sp, maxLines = 2,
                 modifier = Modifier.padding(bottom = 4.dp))
        }

        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
            TextButton(onClick = {
                clipboard.setText(AnnotatedString(text))
                info = "已复制 ${text.length} 字"
            }) { Text("复制") }

            TextButton(onClick = {
                scope.launch {
                    info = try {
                        val dir = ctx.getExternalFilesDir(null) ?: ctx.filesDir
                        val f = File(dir, "dfroot-${System.currentTimeMillis()}.log")
                        withContext(Dispatchers.IO) { f.writeText(text) }
                        "已导出 ${f.absolutePath}"
                    } catch (t: Throwable) {
                        "导出失败: ${t.message}"
                    }
                }
            }) { Text("导出") }

            TextButton(onClick = { OutputLog.clear(); text = ""; info = null }) { Text("清空") }
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
    alpha: Float = 1f,
    onClick: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth()
            .height(height.dp)
            .alpha(alpha)
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
