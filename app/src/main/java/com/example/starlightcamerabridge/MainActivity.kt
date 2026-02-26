package com.example.starlightcamerabridge

import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.example.starlightcamerabridge.adb.AdbClient
import com.example.starlightcamerabridge.adb.AdbConnectionPreferences
import com.example.starlightcamerabridge.adb.AdbRootPasswordPreferences
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val inputRootPassword = findViewById<TextInputEditText>(R.id.inputRootPassword)
        val btnSavePassword = findViewById<MaterialButton>(R.id.btnSavePassword)

        val inputAdbHost = findViewById<TextInputEditText>(R.id.inputAdbHost)
        val inputAdbPort = findViewById<TextInputEditText>(R.id.inputAdbPort)
        val inputAdbCommand = findViewById<TextInputEditText>(R.id.inputAdbCommand)
        val btnExecute = findViewById<MaterialButton>(R.id.btnExecute)
        val tvOutput = findViewById<TextView>(R.id.tvOutput)

        val savedPassword = AdbRootPasswordPreferences.getPassword(this)
        if (savedPassword.isNotBlank()) {
            inputRootPassword.setText(savedPassword)
        }

        inputAdbHost.setText(AdbConnectionPreferences.getHost(this))
        inputAdbPort.setText(AdbConnectionPreferences.getPort(this).toString())

        val btnSaveConnection = findViewById<MaterialButton>(R.id.btnSaveConnection)
        btnSaveConnection.setOnClickListener {
            val host = inputAdbHost.text?.toString()?.trim().orEmpty()
            if (host.isBlank()) {
                toast(getString(R.string.adb_host_empty))
                return@setOnClickListener
            }
            val port = inputAdbPort.text?.toString()?.trim()?.toIntOrNull()
            if (port == null || port !in 1..65535) {
                toast(getString(R.string.adb_port_invalid))
                return@setOnClickListener
            }
            AdbConnectionPreferences.save(this, host, port)
            toast(getString(R.string.adb_connection_saved))
        }

        btnSavePassword.setOnClickListener {
            val pwd = inputRootPassword.text?.toString()?.trim().orEmpty()
            if (pwd.isBlank()) {
                toast(getString(R.string.adb_root_password_empty))
                return@setOnClickListener
            }
            AdbRootPasswordPreferences.setPassword(this, pwd)
            toast(getString(R.string.adb_password_saved))
        }

        btnExecute.setOnClickListener {
            val host = inputAdbHost.text?.toString()?.trim().orEmpty()
            if (host.isBlank()) {
                toast(getString(R.string.adb_host_empty))
                return@setOnClickListener
            }
            val port = inputAdbPort.text?.toString()?.trim()?.toIntOrNull()
            if (port == null || port !in 1..65535) {
                toast(getString(R.string.adb_port_invalid))
                return@setOnClickListener
            }
            val command = inputAdbCommand.text?.toString()?.trim().orEmpty()
            if (command.isBlank()) {
                toast(getString(R.string.adb_command_empty))
                return@setOnClickListener
            }

            tvOutput.text = getString(R.string.adb_command_running)
            btnExecute.isEnabled = false

            lifecycleScope.launch {
                val client = AdbClient(this@MainActivity)
                try {
                    client.connect(host, port)
                    val output = client.executeShellCommand(command)
                    tvOutput.text = output.trim().ifEmpty { "(no output)" }
                } catch (e: Exception) {
                    tvOutput.text = "${getString(R.string.adb_command_failed)}: ${e.message}"
                } finally {
                    client.close()
                    btnExecute.isEnabled = true
                }
            }
        }

        // ===== Frida 注入区 =====

        val btnFridaInject = findViewById<MaterialButton>(R.id.btnFridaInject)
        val btnFridaRestore = findViewById<MaterialButton>(R.id.btnFridaRestore)
        val tvFridaLog = findViewById<TextView>(R.id.tvFridaLog)
        val scrollFridaLog = findViewById<ScrollView>(R.id.scrollFridaLog)

        val fridaDeployer = FridaDeployer(applicationContext)

        /**
         * 向 Frida 日志区追加一行文本，并自动滚到底部。
         */
        fun appendFridaLog(msg: String) {
            val current = tvFridaLog.text.toString()
            val newText = if (current == getString(R.string.frida_log_idle)) msg else "$current\n$msg"
            tvFridaLog.text = newText
            scrollFridaLog.post { scrollFridaLog.fullScroll(ScrollView.FOCUS_DOWN) }
        }

        /**
         * 读取当前 Host/Port 配置。
         *
         * @return (host, port) 或 null 表示参数无效
         */
        fun readHostPort(): Pair<String, Int>? {
            val host = inputAdbHost.text?.toString()?.trim().orEmpty()
            if (host.isBlank()) {
                toast(getString(R.string.adb_host_empty))
                return null
            }
            val port = inputAdbPort.text?.toString()?.trim()?.toIntOrNull()
            if (port == null || port !in 1..65535) {
                toast(getString(R.string.adb_port_invalid))
                return null
            }
            return host to port
        }

        btnFridaInject.setOnClickListener {
            val hp = readHostPort() ?: return@setOnClickListener
            btnFridaInject.isEnabled = false
            btnFridaRestore.isEnabled = false
            tvFridaLog.text = ""

            lifecycleScope.launch(Dispatchers.Main) {
                fridaDeployer.inject(hp.first, hp.second) { msg ->
                    // 回调可能在 IO 线程，切到主线程
                    launch(Dispatchers.Main) { appendFridaLog(msg) }
                }
                btnFridaInject.isEnabled = true
                btnFridaRestore.isEnabled = true
            }
        }

        btnFridaRestore.setOnClickListener {
            val hp = readHostPort() ?: return@setOnClickListener
            btnFridaInject.isEnabled = false
            btnFridaRestore.isEnabled = false
            tvFridaLog.text = ""

            lifecycleScope.launch(Dispatchers.Main) {
                fridaDeployer.restore(hp.first, hp.second) { msg ->
                    launch(Dispatchers.Main) { appendFridaLog(msg) }
                }
                btnFridaInject.isEnabled = true
                btnFridaRestore.isEnabled = true
            }
        }

        // ===== 注入流程完毕 =====
    }

    /**
     * 显示短提示信息。
     *
     * @param message 提示文本
     */
    private fun toast(message: String) {
        android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_SHORT).show()
    }
}
