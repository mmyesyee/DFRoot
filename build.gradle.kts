// AGP 9 compiles Kotlin itself (built-in Kotlin 2.2.10) and registers the
// 'kotlin' extension, so org.jetbrains.kotlin.android must NOT be applied.
// Compose still needs its compiler plugin, and that plugin has to match the
// bundled Kotlin exactly.
plugins {
    id("com.android.application") version "9.4.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
}
