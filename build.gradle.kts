// AGP 9 compiles Kotlin itself (built-in Kotlin), so the Kotlin Android Gradle
// plugin must NOT be applied here: it tries to register a second 'kotlin'
// extension and fails with "Cannot add extension with name 'kotlin'".
plugins {
    id("com.android.application") version "9.4.0" apply false
}
